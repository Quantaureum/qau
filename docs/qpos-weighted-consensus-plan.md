# QPOS weighted election and committee partitioning — overall design (R101/R102/R103)

> Status: R101 merged and deployed; R104 (pruning accidentally dropped the justified root) and R105-FINALITY-TARGET-BINDING (network-wide finality freeze caused by a mismatch between R42-P4 boundary roots and per-slot counts) are both fixed and deployed; R102/R103 are implemented (epoch-gated, off by default); before the mainnet upgrade all nodes must configure the same weightedConsensusCutoverEpoch; Phase 3 QTD aggregation awaits a later design.


> 2026-08-30 audit-driven. Background: the user asked to "mimic Ethereum's weighting and committees" and authorized full implementation.
> This document is the single authoritative plan; implementation proceeds in incremental numbered R commits — big-bang switches are forbidden.

## 0. Current-state audit findings (code facts, all verified)

| Component | Current state | File ||
|------|------|------|
| Proposer election | Fisher-Yates full shuffle, `shuffled[slotInEpoch]`, **not stake-weighted** | `consensus/qpos_proposer.go` ||
| Committee | with `n<=32` everyone votes every slot; with `n>32` each slot **samples** `min(n/32,128)` from the shuffle, with cross-slot repetition | `consensus/qpos_committee.go` ||
| Finality formula | `attestedWeight*3 >= totalWeight*2`; the numerator counts only voters, the denominator all active | `consensus/qpos_finality.go` ||
| Header finality fields | display-only in logs, **never cross-validated** | `core/block_validator.go` ||
| In-block attestations | only size/format checks, no committee eligibility check | `core/block_validator.go:1528` ||
| Gossip attestations | non-members rejected (local-node counting only) | `consensus/validator.go:149` ||
| Proposer identity | **enforced during block validation** (`invalid block proposer`) | root cause of the R88 incident ||

### Three proven defects

1. **F1 (finality mathematical ceiling)**: with n > 6144, `attestedWeight/totalWeight <= 4096/n < 2/3` — finality becomes mathematically impossible. Measured: 6144 works exactly, 6145 fails.
2. **F2 (economic security)**: proposers are not stake-weighted, so a 32 QAU registration equals the block-proposal right of a 6000 QAU genesis validator. At n=20000, an attacker with 640k QAU can control 50% of block production.
3. **F3 (restart deadlock)**: `epochBlockRoots` lives only in memory; after a restart the boundary root of the justified epoch (e.g. =27) is missing, so `tryUpdateFinality` fail-closed skips all attestations with `Source.Epoch=27` -> justified freezes at 27 forever -> finalized stays 0 forever -> Inactivity Leak stays active forever and the header's `finalizedEpoch` reads 0. Reproduced with the `consensus` probe (cold start at epoch 28 -> nine epochs of no progress; continuous running from epoch 1 progresses normally 3/2->4/3->...).

## 1. Fork-sensitivity classification (determines deployment)

| Change | Fork-sensitive | Reason | Deployment ||
------|---------|------|---------||
| R101 finality root backfill | **No** | `finalizedEpoch` is write-only in headers; attestation counting is node-local | normal rolling deployment ||
| R103 committee partitioning (covers everyone) | **No** | committee eligibility only affects whether a node counts an attestation, not block validity | normal rolling deployment ||
| R102 stake-weighted proposer | **Yes** | `invalid block proposer` is strictly enforced | **epoch-gated switch**: the new binary ships the old rules and activates `cutoverEpoch` network-wide ||

## 2. R101-FINALITY-RESUME (first, non-forking)

**Mechanism**: an epoch root is produced by "the first block of that epoch" (a boundary-slot block -> its own hash; otherwise -> its ParentHash). After a node restart completes syncing, it walks back from the chain head through at most ~160 blocks in the local `BlockStore`, rebuilds the roots of the 4 most recently completed epochs, and injects them into `epochBlockRoots`.

- New API: `consensus.(*QPOS).BackfillEpochRoots(map[uint64]types.Hash)` (direct write, avoiding per-entry inserts that could trigger pruning cascades)
- Integration point: `node.Syncer.checkSync()`, throttled per epoch (once per epoch)
- Test: reproduce "justified stuck after restart" -> backfill -> justification/finalization resumes
- Finality-state persistence is **out of scope** (separate topic, a later R)

## 3. R102-WEIGHTED-PROPOSER (fork-sensitive, epoch-gated)

**Algorithm** (deterministic, no floats, verifiable):
```
totalWeight = Σ active.Stake (snapshot-consistent within an epoch: activation goes through the ValidatorQueue 4-epoch delay, which is itself epoch-boundary semantics)
for slot in epoch:
    target = keccak(epochSeed ‖ slotInEpoch) mod totalWeight
    walk active validators' stakes in order; the first whose cumulative sum exceeds target is the proposer
```
- epochSeed keeps the existing `keccak(epoch || VRF-acc[epoch-2])` (no randomness-source change)
- slashed/inactive skip semantics stay as-is (weight counted as 0)
- Gating: `QPOS.SetWeightedProposerCutover(epoch)`; `epoch < cutover` takes the old Fisher-Yates path; default `math.MaxUint64` (unconfigured = old behavior, **fail-safe**)
- Node config: `config.json` gains `consensusCutoverEpoch`, the same value on all 7 nodes
- Test matrix: chi-square test on the weighted distribution (large-sample frequency ~ weight ratio), equal weights ~ uniform, pre/post-cutover determinism of both paths, cross-node determinism (same input, same output), zero-stake / single-validator / large-skew boundaries

## 4. R103-COMMITTEE-PARTITION (non-forking, covers everyone)

Change the `n>32` committee from "sample per slot" to "partition per epoch" (Ethereum style):
```
committeesPerSlot = max(1, ceil(n / (SlotsPerEpoch * TargetCommitteeSize)))   // n=20000 → 2
Each epoch: shuffle once, then slice the shuffled list into committeesPerSlot*32 segments;
slot s's k-th committee = segment [s*committeesPerSlot + k]
Every validator lands in exactly one committee per epoch -> everyone votes once -> attestedWeight ceiling returns to ~100%
```
- Partitioning splits evenly by index (not weighted); weights are only applied at counting time, as in Ethereum (their index carries an equal 32 ETH; we multiply by Stake directly at count time — simpler)
- `IsInCommittee` / `getCommitteeForSlotLocked` updated in step; the `n<=32` small-network path stays all-members
- In-block attestation size: at large n, handled by QTD aggregation (R104+, separate effort); protocol correctness first
- Tests: at 20000 validators everyone is in exactly one committee per epoch; at n=6145/20000 finality 2/3 is reachable (F1 regression); small-network behavior unchanged

## 5. Order and acceptance

1. R101 (this round): code + repro/regression tests + all green locally -> commit -> rolling restart of the 7 nodes -> verify justified/finalized resume online
2. R102 + R103 share one epoch gate (one switch accomplishes both, minimizing hard cutovers)
3. Deployment is allowed only after everything passes CI (`golangci-lint`, `gofmt -s`, full consensus-package tests)

## 6. Explicitly out of scope (this phase)

- QTD signature aggregation (R104+, separate effort)
- Finality-state persistence (R105 candidate)
- Economic-parameter tuning of `MaxValidators=250000` and the 32 QAU threshold (re-evaluate after weighting ships)
- Review chamber restructuring (orthogonal to this effort)

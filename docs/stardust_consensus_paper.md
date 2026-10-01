# Stardust Consensus: Post-Quantum Instant Finality through Three-Chamber Separation of Powers

**Authors**: Quantaureum Engineering Team
**Date**: June 8, 2026
**Version**: 1.0
**Contact**: research@quantaureum.com

---

## Abstract

We present Stardust Consensus, a post-quantum blockchain consensus protocol that achieves instant finality through a novel Three-Chamber separation-of-powers architecture combined with QTD (Quantaureum Threshold Dilithium) threshold signing. Drawing inspiration from the Chinese imperial Three Departments and Six Ministries system and the Daoist principle that "the Dao produces one, one produces two, two produce three, and three produce all things," Stardust separates consensus authority into three mutually constraining chambers: the Executive Chamber (Zhongshu Sheng) proposes blocks via post-quantum VRF election, the Review Chamber (Menxia Sheng) attests blocks through a 128-member committee with 2/3 supermajority veto power, and the Seal Chamber (Shangshu Sheng) finalizes blocks via a 3-member QTD committee producing a single 2-of-3 Dilithium3 threshold signature. This design reduces finality latency from approximately 13 minutes (Casper FFG) to under 6 seconds, while enabling constant-size finality proofs verifiable by light clients with a single signature verification. The protocol is implemented in Go (~4,000 lines) with 43 QTD unit tests and 28 Stardust integration tests, and supports 200,000 validators with O(log n) proposer selection and O(1) validator lookup.

**Keywords**: post-quantum, threshold signature, instant finality, consensus, Dilithium3, separation of powers

---

## 1. Introduction

### 1.1 The Finality Problem in Blockchain

Blockchain finality - the guarantee that a confirmed transaction will never be reversed - is the cornerstone of trustless distributed systems. In proof-of-stake blockchains, finality is typically achieved through multi-epoch attestation processes. Ethereum's Gasper consensus, combining Casper FFG [1] with LMD GHOST, requires approximately 13 minutes (2 epochs of 32 slots each at 12 seconds per slot) for a block to become finalized. During this window, blocks are subject to reorganization, creating uncertainty for applications that require settlement assurance.

Several protocols have attempted to address this latency. Tendermint [2] achieves deterministic finality in 2-5 seconds through all-to-all voting, but at the cost of requiring every validator to communicate with every other validator - a quadratic communication overhead that limits scalability. HotStuff [3] improves communication complexity to linear through pipelined three-phase voting, but still requires multiple rounds of message exchange before finality. Algorand [4] uses cryptographic sortition for committee selection but relies on BA* for agreement, which still requires multiple steps.

### 1.2 The Post-Quantum Challenge

All widely deployed proof-of-stake protocols use classical signature schemes (BLS, Ed25519, secp256k1) that are vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. NIST standardized CRYSTALS-Dilithium [5] as FIPS 204 [6] for post-quantum digital signatures, but Dilithium3 signatures are 3,293 bytes - approximately 20x larger than BLS12-381 signatures (48 bytes) and 65x larger than Ed25519 signatures (64 bytes). This size amplification makes naive replacement of classical signatures in existing consensus protocols prohibitively expensive: a Tendermint-style all-to-all vote among 128 validators would require 128 x 3,293 = 421,504 bytes of signature data per round, compared to 128 x 48 = 6,144 bytes with BLS aggregation.

### 1.3 Our Contributions

We present Stardust Consensus, which makes the following contributions:

1. **Three-Chamber Architecture.** A separation-of-powers consensus design inspired by the Chinese imperial Three Departments and Six Ministries system. Authority is divided into three mutually constraining chambers - Executive, Review, and Seal - each with distinct roles and veto capabilities, preventing any single entity from unilaterally controlling the consensus process.

2. **Instant Finality via QTD Threshold Signatures.** By combining the Three-Chamber architecture with QTD 2-of-3 threshold signing over Dilithium3, we achieve block finality in under 6 seconds - a single slot duration - with a constant-size finality proof of 3,293 bytes, regardless of the total number of validators.

3. **Post-Quantum Security.** All cryptographic operations - VRF election, attestation signing, and threshold finalization - use Dilithium3, providing security against quantum adversaries.

4. **Scalable Validator Support.** The protocol supports 200,000 validators through O(log n) stake-weighted proposer selection via binary search on cumulative stakes, O(1) validator lookup via address-indexed maps, and committee caching.

5. **Graceful Degradation.** When QTD threshold signing is unavailable, the protocol falls back to Casper FFG finality, ensuring liveness under adverse conditions.

---

## 2. Background

### 2.1 Blockchain Finality

**Casper FFG** [1] is a finality gadget that overlays a proof-of-stake blockchain. Validators vote on checkpoints (epoch boundaries), and a checkpoint becomes justified when 2/3 of the total stake votes for it, then finalized when the next checkpoint is justified. The two-epoch delay (approximately 13 minutes at 32 slots/epoch and 12 seconds/slot) is inherent to the design: finality requires observing two consecutive justified epochs.

**Tendermint** [2] achieves deterministic finality through a three-phase protocol (pre-vote, pre-commit, commit) in which a block is finalized as soon as 2/3+ of validators sign a commit message. Finality latency is typically 2-5 seconds but requires O(n^2) communication for n validators.

**HotStuff** [3] pipelines the three-phase voting across consecutive blocks, achieving linear communication complexity per round through a leader-based approach. It provides expected finality in 3 rounds of communication.

### 2.2 Post-Quantum Signatures

**CRYSTALS-Dilithium** [5] is a lattice-based digital signature scheme based on the hardness of Module-LWE and Module-SIS problems. Dilithium3, the parameter set recommended for NIST Security Level 5, uses a 6x5 matrix structure over the ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ with $q = 8380417$. A Dilithium3 signature $(z, h, c)$ is approximately 3,293 bytes.

**FIPS 204** [6] standardizes Dilithium as the Module-Lattice-Based Digital Signature Standard, making it the primary post-quantum signature algorithm for US government use.

### 2.3 Threshold Signatures

**FROST** [7] is a two-round threshold signing protocol for Schnorr signatures that achieves flexible round optimization. It uses additive secret sharing and binding commitments to prevent forgery attacks.

**Boneh et al.** [8] construct a threshold Dilithium scheme using garbled circuits to securely evaluate the rejection sampling step, achieving malicious security in the UC framework at the cost of substantial computational overhead.

**Katsumata et al.** [9] present the first lattice-based two-round threshold signature scheme using linear secret sharing and lattice-based NIZK proofs, achieving strong security but requiring heavyweight cryptographic machinery.

QTD [10] takes an engineering-oriented approach: by accepting semi-honest security, it achieves a simple two-round protocol that produces standard Dilithium3-compatible signatures through direct algebraic manipulation of the signing equation.

---

## 3. QTD Protocol

QTD (Quantaureum Threshold Dilithium) is the threshold signing protocol that underpins Stardust's instant finality. We summarize its key properties here; the full specification is available in [10].

### 3.1 Weighted Response Linearity

The foundation of QTD is the following algebraic observation:

**Lemma 1 (Weighted Response Linearity).** Let $s_{1,1}, \ldots, s_{1,t} \in R_q^l$ be Shamir shares of $s_1 \in R_q^l$ with Lagrange coefficients $\lambda_1, \ldots, \lambda_t$. Let $y_1, \ldots, y_t \in R_q^l$ be arbitrary vectors, let $c$ be any polynomial in $R_q$, and define $y_{\text{agg}} = \sum_{i=1}^t y_i$. Then:

$$z = \sum_{i=1}^t (\lambda_i \cdot s_{1,i} \cdot c + y_i) = s_1 \cdot c + y_{\text{agg}}$$

**Proof.** $\sum_i (\lambda_i \cdot s_{1,i} \cdot c + y_i) = \left(\sum_i \lambda_i \cdot s_{1,i}\right) \cdot c + \sum_i y_i = s_1 \cdot c + y_{\text{agg}}$. The first equality uses distributivity of polynomial multiplication; the second uses the reconstruction property of Shamir sharing and the definition of $y_{\text{agg}}$. $\square$

Crucially, the Lagrange coefficients $\lambda_i$ are applied only to the secret-key-dependent term $s_{1,i} \cdot c$, not to the masking term $y_i$. The masking contributions combine via direct summation, ensuring that both $w = A \cdot y_{\text{agg}}$ and $z = s_1 \cdot c + y_{\text{agg}}$ use the same aggregated masking vector.

### 3.2 Two-Round Signing

**Round 1: Masking Commitment.** Each party $P_i$ samples $y_i \leftarrow S_{\eta_2}^l$ (coefficients in $[-\eta_2, \eta_2]$ where $\eta_2 = 72$), computes $w_i = A \cdot y_i$, and broadcasts commitment $D_i = \text{SHA-256}(w_i \| i \| n_i)$.

**Round 2: Reveal and Response.** After receiving all commitments, each party reveals $(w_i, n_i)$. All parties verify commitments, compute $w_{\text{agg}} = \sum_{j \in I} w_j$, derive the challenge $c = \text{SampleInBall}(\text{SHA-256}(\text{HighBits}(w_{\text{agg}}, \gamma_2) \| M))$, and compute their response share:

$$z_i = \lambda_i \cdot s_{1,i} \cdot c + y_i$$

**Aggregation.** The coordinator computes $z = \sum_{i \in I} z_i$, verifies $\|z\|_\infty \leq \gamma_1 - \beta$, computes the hint $h$, and outputs the signature $\sigma = (z, h, c)$.

### 3.3 Distributed Key Generation (DKG)

QTD-DKG uses a commitment-reveal structure to prevent last-revealer attacks:

1. Each party $P_i$ samples a seed contribution $\xi_i$ and broadcasts commitment $C_i = \text{SHA3-256}(\xi_i \| i \| r_i)$.
2. After all commitments are collected, parties reveal their seeds.
3. The global seed is $\xi = \text{SHA-256}(\xi_1 \| \xi_2 \| \ldots \| \xi_n)$ (cascade, not XOR, to prevent adaptive seed selection).
4. Key material is expanded from $\xi$ using SHAKE-256.
5. Shamir sharing is applied coefficient-wise to $s_1$ and $s_2$.
6. Pedersen verification vectors over BLS12-381 enable independent share verification.

### 3.4 Correctness Theorem

**Theorem 1.** If all parties follow the protocol and the rejection check passes, the output $\sigma = (z, h, c)$ is a valid Dilithium3 signature on message $M$ under public key $pk$.

The proof follows directly from Lemma 1 and the equivalence of the aggregated values $w_{\text{agg}}$, $z$, $c$, and $h$ to their standard Dilithium3 counterparts. See [10] for the full proof.

### 3.5 Security Properties

**Semi-honest EUF-CMA.** In the semi-honest model, QTD is existentially unforgeable under chosen-message attacks, assuming the EUF-CMA security of standard Dilithium3. This is a direct reduction: any QTD forgery is a valid Dilithium3 forgery.

**Threshold secrecy.** Any coalition of fewer than $t$ semi-honest parties learns nothing about the private key beyond what is implied by the public key, by the information-theoretic security of Shamir secret sharing over $\mathbb{Z}_q$.

**Masking distribution trade-off.** The most significant deviation from standard Dilithium3 is the narrowed masking distribution. In standard Dilithium3, $y$ coefficients are uniform in $[-524287, 524287]$; in QTD with $t = 3$, $y_{\text{agg}}$ coefficients are in $[-216, 216]$. This eliminates the need for rejection sampling (since $\|z\|_\infty \leq 195 + 216 = 411 \ll 522368 = \gamma_1 - \beta$) but means the protocol does not satisfy statistical zero-knowledge in the standard Dilithium3 sense. The conditional distribution of $z$ given $c$ reveals more information about $s_1 \cdot c$ than in standard Dilithium3. We discuss mitigations in Section 10.

---

## 4. Three-Chamber Architecture

### 4.1 Design Philosophy

The Three-Chamber architecture is inspired by the Chinese imperial Three Departments system, which divided executive authority among three mutually constraining departments:

- **Secretariat (Zhongshu Sheng)**: Drafts imperial edicts - analogous to block proposal
- **Chancellery (Menxia Sheng)**: Reviews and may veto edicts - analogous to attestation with veto power
- **Department of State Affairs (Shangshu Sheng)**: Executes approved edicts - analogous to finalization via threshold signature

This design also resonates with the Daoist principle from the *Tao Te Ching*: "The Dao produces one, one produces two, two produce three, and three produce all things." The QTD 2-of-3 threshold corresponds to this principle: three sealers, any two of which can produce a valid signature, enabling the system to "produce all things" - i.e., achieve instant finality.

The key insight is that separation of powers is not merely a governance philosophy but a concrete security mechanism. By requiring three distinct authorities to act in sequence, with each authority having the power to block the process, the system prevents any single point of failure or corruption from compromising consensus integrity.

### 4.2 Executive Chamber (Zhongshu Sheng / Proposer)

The Executive Chamber is responsible for block proposal. For each 12-second slot, a single proposer is selected through post-quantum VRF (PQ-VRF) election.

**Proposer Selection.** The PQ-VRF protocol uses Dilithium3 as the underlying signature scheme. A validator evaluates the VRF on a seed derived from the previous block hash and the current slot number, producing a VRF proof and output. The VRF output is combined with multiple entropy sources - including the block hash, timestamp, validator public key, and stake ratio components - and hashed with SHA3-256 to produce a final selection value. This enhanced entropy prevents stake manipulation attacks where a validator might attempt to bias the election outcome.

**Stake-weighted selection.** The validator set maintains precomputed cumulative stakes, enabling O(log n) binary search for proposer selection. Given a VRF output value $v$, the selection point is $v \bmod \text{totalStake}$, and binary search on the cumulative stake array identifies the selected validator. This is critical for supporting 200,000+ validators efficiently.

**Slot structure.** Each slot is 12 seconds, with 32 slots per epoch (6.4 minutes). One block is produced per slot. The proposer must not simultaneously serve in the Review or Seal chambers, enforced by the `ThreeChambersCoordinator`'s cross-chamber conflict detection.

### 4.3 Review Chamber (Menxia Sheng / Attestation)

The Review Chamber is responsible for attesting proposed blocks. It exercises the power of *fengbo* (veto/rejection) - a critical check on the Executive Chamber.

**Committee composition.** For each slot, a committee of up to 128 validators is selected from the active validator set. The committee size is bounded by `TargetCommitteeSize = 128`, a parameter chosen to balance security (sufficient decentralization) with efficiency (manageable communication overhead).

**Attestation process.** Each committee member independently verifies the proposed block and submits an attestation signed with their Dilithium3 key. The Review Chamber tracks attestations and evaluates the verdict:

- **Approved**: When the cumulative stake of approving validators reaches 2/3 of the total committee stake.
- **Rejected**: When the cumulative stake of rejecting validators reaches 2/3 of the total committee stake.
- **Timeout**: If no verdict is reached within the 6-second attestation timeout.

The 2/3 supermajority threshold ensures that no single entity controlling less than 1/3 of the stake can either force approval or force rejection, providing Byzantine fault tolerance.

**Veto power.** The Review Chamber's veto power is absolute: if a block is rejected or times out, it cannot proceed to the Seal Chamber. This is the *fengboquan* (veto power) - the power to reject an imperial edict. In the Chinese system, this prevented the emperor from issuing arbitrary decrees; in Stardust, it prevents a malicious proposer from finalizing invalid blocks.

**Anti-replay protection.** Attestations include a network ID domain separator and a key version field, preventing cross-chain replay and post-key-rotation forgery. Stale attestations (older than one epoch) are rejected.

### 4.4 Seal Chamber (Shangshu Sheng / QTD Finalization)

The Seal Chamber is responsible for finalizing approved blocks through QTD threshold signing. It is the mechanism by which approved edicts become immutable law.

**Committee composition.** The Seal Chamber consists of 3 validators selected per epoch through a stake-weighted random selection process. The selection uses an epoch-specific seed derived from the RANDAO mix, combined with each validator's stake to produce a deterministic but unpredictable ordering. The top 3 validators by score are selected, excluding those already serving in the Executive or Review chambers.

**2-of-3 threshold.** The Seal Chamber operates with a 2-of-3 threshold: any 2 of the 3 sealers can produce a valid QTD threshold signature. This provides:

- **Liveness**: The system can tolerate 1 sealer being offline or unresponsive.
- **Security**: At least 2 sealers must collude to produce an unauthorized signature.
- **Efficiency**: Only 2 parties need to participate in the signing protocol.

**DKG lifecycle.** At the start of each epoch, the newly selected Seal Chamber members run QTD-DKG to establish their shared key. The lifecycle proceeds through four states:

1. **Idle**: No members assigned.
2. **DKGRunning**: Members assigned, distributed key generation in progress.
3. **Active**: DKG complete, group public key established, ready to seal blocks.
4. **Sealing**: Actively producing threshold signatures for approved blocks.

**Signature production.** When a block is approved by the Review Chamber, the Seal Chamber initiates QTD signing. The two-round protocol (commitment, then reveal-and-response) produces a single Dilithium3 signature of 3,293 bytes. This signature is the *finality proof* - it attests that 2-of-3 sealers have confirmed the block, and it is verifiable by any party with the group public key.

**Instant finality.** Once the QTD signature is produced, the block is immediately finalized. The `QTDFinalityState` records the finalization with the signature, sealers, and finality delay. The justified and finalized epochs are updated atomically.

### 4.5 Checks and Balances

The Three-Chamber architecture implements a system of mutual constraints:

**The Executive cannot unilaterally decide.** A proposer creates a block, but it cannot be finalized without Review Chamber approval and Seal Chamber signature. The proposer has no power to force acceptance of its block.

**The Review can veto.** The Review Chamber's 2/3 supermajority requirement means that a block opposed by more than 1/3 of the committee stake will be rejected. This is the *fengboquan* (veto power) - the power to send back an edict. The Review Chamber cannot, however, create blocks or finalize them.

**The Seal cannot alter the decree.** The Seal Chamber signs the block hash as approved by the Review Chamber. It cannot modify the block content - the signature is bound to the specific block hash. The Seal Chamber's role is purely to attest that the proper process was followed.

**Cross-chamber exclusivity.** A validator cannot simultaneously serve in multiple chambers. The `ThreeChambersCoordinator` enforces this through `ChamberAssignment` tracking, returning errors such as `ErrProposerPowerExceeded`, `ErrReviewPowerExceeded`, and `ErrExecutivePowerExceeded` when a validator attempts to serve in a second chamber.

**Collusion detection.** The QTD implementation includes timing-based and share-similarity-based collusion detection. If two sealers consistently submit their shares with suspicious timing correlation or if their shares exhibit statistical anomalies suggesting coordination, the system flags the behavior for investigation.

---

## 5. Instant Finality

### 5.1 From Casper FFG to QTD Finality

In Ethereum's Gasper consensus, finality follows the Casper FFG rules:

1. A checkpoint (epoch boundary) is **justified** when 2/3 of stake attests to it.
2. A justified checkpoint becomes **finalized** when the next checkpoint is justified.
3. This requires at least 2 epochs (approximately 13 minutes) from block proposal to finality.

In Stardust Consensus, finality is achieved within a single slot:

1. The proposer creates a block (Executive Chamber).
2. The Review Chamber attests the block within the slot's attestation window (up to 6 seconds).
3. Upon 2/3 approval, the Seal Chamber produces a QTD threshold signature.
4. The block is immediately finalized.

The finality latency is bounded by the slot duration (12 seconds), and in practice, the attestation and sealing process completes in under 6 seconds.

### 5.2 Finality Proof

A Stardust finality proof consists of a single QTD threshold signature (3,293 bytes) plus the block hash and slot number. This is in stark contrast to Casper FFG, where verifying finality requires:

- The full attestation data for two consecutive epochs
- Individual validator signatures (or aggregated BLS signatures with participation bitfields)
- The validator set for the relevant epochs

**Light client verification.** A light client can verify Stardust finality with:

1. The group public key of the Seal Chamber (established once per epoch via DKG)
2. The QTD signature (3,293 bytes)
3. The block hash

This is a single Dilithium3 verification, requiring no sync committee, no attestation data, and no validator set downloads. The verification function `VerifyStardustFinality` in the block header validates the QTD signature against the group public key.

**Comparison with Ethereum light clients.** Ethereum light clients must track the sync committee (512 validators, rotated every 27 hours) and verify aggregate BLS signatures. Stardust light clients need only the Seal Chamber's group public key (3 members, rotated per epoch) and verify a single Dilithium3 signature.

### 5.3 Fallback to Casper FFG

When QTD threshold signing is unavailable - for example, during Seal Chamber reconfiguration, DKG failure, or network partition affecting more than 1 sealer - the protocol gracefully degrades to Casper FFG finality. The `QTDFinalityState` tracks the current finality type:

- `FinalityQTDInstant`: QTD threshold signing is active, blocks are finalized within the slot.
- `FinalityCasperFFG`: QTD is unavailable, blocks are finalized through the standard 2-epoch attestation process.

The fallback is automatic: if the Seal Chamber is not in the `Active` or `Sealing` state, or if the QTD signer is nil, the system reverts to Casper FFG. This ensures liveness under all conditions - the chain continues to produce blocks and achieve eventual finality even when the instant finality mechanism is temporarily unavailable.

---

## 6. Six Ministries

The Three-Chamber architecture is complemented by Six Ministries, each responsible for a specific domain of blockchain governance. These ministries operate under the authority of the Three Chambers and provide structured management of the blockchain's operational concerns.

| Ministry | Chinese | ID | Responsibility |
|----------|---------|-----|---------------|
| Personnel | Libu | 1 | Validator onboarding, registration, and lifecycle management |
| Revenue | Hubu | 2 | Staking economics, reward distribution, and treasury management |
| Justice | Xingbu | 3 | Slashing, dispute resolution, and evidence processing |
| Defense | Bingbu | 4 | Network security, DDoS protection, and attack detection |
| Rites | Libu | 5 | Governance proposals, voting, and protocol upgrades |
| Works | Gongbu | 6 | Sharding, cross-chain bridges, and infrastructure |

**Ministry of Rites (Libu).** The governance module supports proposal creation, stake-weighted voting, and execution. Proposals can be protocol upgrades, parameter changes, emergency actions, or treasury expenditures. Each proposal has a configurable voting period (1 hour to 7 days), quorum (50%), and pass threshold (67%). The ministry enforces a maximum of 100 active proposals simultaneously and maintains a history of up to 1,000 proposals.

**Ministry of Works (Gongbu).** Manages the blockchain's infrastructure layer, including shard registration (up to 64 shards), cross-chain bridge management (up to 32 bridges), and cross-chain transaction tracking (up to 10,000 pending transactions). Each shard and bridge has health monitoring based on last-active timestamps.

**Ministry of Justice (Xingbu).** Processes slashing evidence for double-signing and surround-vote violations. Evidence is queued locally when the slashing manager is unavailable and submitted asynchronously to prevent blocking the consensus hot path.

---

## 7. Scalability

### 7.1 200K Validator Support

Stardust Consensus is designed to support 200,000 validators, matching Ethereum's validator set scale. Key optimizations include:

**O(1) validator lookup.** The `ValidatorSet` maintains an `addrIndexMap` (hash map from address to index) and a `validatorMap` (hash map from address to validator struct), enabling constant-time lookups by address. Previously, `GetValidatorIndex` performed an O(n) linear scan; the indexed map reduces this to O(1).

**O(log n) proposer selection.** The `ValidatorSet` precomputes cumulative stakes, enabling binary search for stake-weighted proposer selection. Given a VRF output, the selection point is $v \bmod \text{totalStake}$, and binary search on the cumulative stake array identifies the selected validator in $O(\log n)$ time.

**Committee caching.** Committee assignments are cached for up to 64 slots, avoiding recomputation of the shuffle algorithm for each slot. The shuffle cache is bounded to 5 entries to prevent unbounded memory growth.

**Memory management.** The system enforces limits on tracked validators (250,000), vote history entries (250,000), evidence queue size (10,000), and attestation history. Automatic pruning removes data older than the finalized epoch.

### 7.2 QTD Committee Size Analysis

The Seal Chamber uses 3 members with a 2-of-3 threshold. We analyze why this is optimal:

**Small committees are efficient.** QTD signing requires two rounds of communication. With 3 members, the communication overhead is minimal: 3 commitments in Round 1, 3 reveals in Round 2. The local computation per party is approximately 20 ms (two rounds of matrix multiplication plus response computation), and network latency dominates the end-to-end signing time.

**Security vs. committee size.** A 2-of-3 threshold tolerates 1 malicious sealer. For $t$-of-$n$ with $n = 3$ and $t = 2$, the adversary must corrupt 2 of 3 sealers to forge a signature. With per-epoch rotation and cross-chamber exclusivity, the probability of corrupting a specific set of sealers is bounded by the stake distribution.

**Redundancy via multiple groups.** For higher security requirements, the system can maintain multiple QTD groups (e.g., 2 groups of 3, requiring 2-of-3 from each group). This provides redundancy at the cost of additional DKG and signing overhead. The current implementation supports a single group per epoch, with multi-group support planned for future work.

**Threshold bound.** For $t \leq 5$, the rejection probability is negligible ($\|z\|_\infty \leq 195 + 72t \leq 555 \ll 522368 = \gamma_1 - \beta$), ensuring deterministic signing latency. We recommend $t \leq 5$ as the practical upper bound for QTD committees.

---

## 8. Implementation and Evaluation

### 8.1 Implementation

Stardust Consensus is implemented in Go as part of the Quantaureum blockchain codebase. The implementation comprises approximately 4,000 lines of Go code across the following modules:

| Module | Files | Lines | Purpose |
|--------|-------|-------|---------|
| QTD Protocol | 10 | ~4,100 | Threshold signing, DKG, polynomial arithmetic |
| Three Chambers | 5 | ~1,200 | Chamber coordination, assignment, cross-chamber enforcement |
| Executive Chamber | 1 | ~220 | Seal Chamber lifecycle, DKG state management |
| Review Chamber | 1 | ~280 | Attestation processing, verdict evaluation |
| QTD Finality | 1 | ~300 | Instant finality state, seal requests, verification |
| Ministries | 6 | ~1,500 | Six Ministry implementations |
| PQ-VRF | 1 | ~250 | Post-quantum VRF for proposer election |
| RPC API | 1 | ~280 | Stardust JSON-RPC endpoints |
| Tests | 4 | ~1,400 | 43 QTD tests + 28 Stardust integration tests |

### 8.2 Performance

All measurements on x86_64 at 3.2 GHz (single core):

| Operation | Time | Notes |
|-----------|------|-------|
| QTD DKG (3 parties) | 5.93 ms | Seed commitment, Shamir sharing, Pedersen verification |
| QTD Signing (2-of-3) | 36.04 ms | Two rounds: commitment + reveal/response |
| QTD Verify | 14.30 ms | Standard Dilithium3 verification |
| PQ-VRF Evaluate | ~9.8 ms | Dilithium3-based VRF |
| PQ-VRF Verify | ~14.3 ms | Dilithium3 signature verification |
| Full signing round (per party) | ~9.8 ms | Including masking, matrix mult, response |
| **Finality per slot** | **~5.4 us** | State update after QTD signature verification |
| **200K validators: committee allocation** | **6.1 ms/slot** | O(log n) proposer selection + committee shuffle |

**End-to-end finality latency.** The critical path for instant finality is:

1. Block proposal: ~0 ms (proposer has precomputed the block)
2. Review Chamber attestation: ~3-6 seconds (network propagation + attestation collection)
3. Seal Chamber QTD signing: ~36 ms (two rounds of signing)
4. Finality state update: ~5.4 us

Total: **< 6 seconds** from block proposal to finality, compared to **~13 minutes** for Casper FFG.

### 8.3 Comparison

| Property | Stardust | Ethereum Gasper | Tendermint | HotStuff |
|----------|----------|-----------------|------------|----------|
| Finality latency | < 6s | ~13 min | 2-5s | 3 rounds |
| Post-quantum | Yes (Dilithium3) | No (BLS12-381) | No (Ed25519) | No |
| Finality proof size | 3,293 bytes | ~48 bytes (BLS agg) | n x 64 bytes | n x 64 bytes |
| Light client | 1 signature | Sync committee | Full validator set | Full validator set |
| Checks and balances | 3 chambers | 2 layers (FFG + LMD) | None | None |
| Validator scalability | 200K+ | 1M+ | ~1K | ~1K |
| Communication complexity | O(1) for finality | O(n) per epoch | O(n^2) per round | O(n) per round |
| Graceful degradation | Casper FFG fallback | N/A | N/A | N/A |
| Signature algorithm | Dilithium3 | BLS12-381 | Ed25519 | BLS12-381 |

**Key trade-offs.** Stardust achieves instant finality with a single signature verification, but at the cost of larger signature sizes (3,293 bytes vs. 48 bytes for BLS aggregation). The Three-Chamber architecture provides stronger separation of powers than Ethereum's two-layer (FFG + LMD GHOST) approach, but introduces additional complexity in chamber coordination and DKG management.

---

## 9. Related Work

**Ethereum (Gasper).** Ethereum's consensus protocol [1] combines Casper FFG for finality with LMD GHOST for fork choice. Finality requires 2 epochs (~13 minutes). Gasper uses BLS12-381 aggregate signatures to compress multiple validator attestations into a single signature. Stardust replaces the multi-epoch finality process with a single QTD threshold signature, reducing latency by over 99%.

**Tendermint.** Tendermint [2] achieves deterministic finality through all-to-all voting in three phases. Its O(n^2) communication complexity limits validator set size. Stardust's Three-Chamber architecture decouples proposal, attestation, and finalization, enabling each chamber to operate with its own optimal committee size.

**HotStuff.** HotStuff [3] achieves linear communication complexity through pipelined three-phase voting and a rotating leader. It provides expected finality in 3 rounds. Stardust achieves finality in a single slot by replacing the multi-round voting with a single threshold signature from the Seal Chamber.

**Algorand.** Algorand [4] uses cryptographic sortition for committee selection and BA* for Byzantine agreement. It achieves probabilistic finality with high probability after a few blocks. Stardust achieves deterministic instant finality through the Seal Chamber's threshold signature.

**Solana.** Solana uses Proof of History for timestamping and Tower BFT for consensus. It achieves sub-second block times but does not provide instant finality - blocks can be skipped if the fork choice changes. Stardust's QTD-based finality is deterministic once the Seal Chamber signature is produced.

**QRL.** The Quantum Resistant Ledger [11] uses XMSS (eXtended Merkle Signature Scheme) for post-quantum signatures. XMSS is stateful and requires careful key management to prevent signature reuse. Stardust uses Dilithium3, which is stateless and standardized as FIPS 204, providing a more practical foundation for post-quantum consensus.

---

## 10. Limitations and Future Work

### 10.1 Semi-honest Security

The QTD protocol is secure against semi-honest (passive) adversaries. Malicious parties can deviate from the protocol in ways that produce invalid signatures or potentially leak information. Extending to malicious security requires additional zero-knowledge proofs for correct share computation, which would increase the protocol's complexity and round count. We are investigating the application of garbled-circuit-based rejection sampling (as in Boneh et al. [8]) and lattice-based NIZKs (as in Katsumata et al. [9]) as potential paths to malicious security.

### 10.2 Zero-Knowledge Analysis

The narrowed masking distribution in QTD (coefficients in $[-72t, 72t]$ vs. $[-524287, 524287]$ in standard Dilithium3) means the protocol does not satisfy statistical zero-knowledge. The conditional distribution of $z$ given $c$ reveals more information about $s_1 \cdot c$ than in standard Dilithium3. While this does not directly enable key recovery (since $s_1 \cdot c$ has at most $\tau = 39$ non-zero coefficients per polynomial), a rigorous concrete security analysis is needed to quantify the attacker's advantage. Potential mitigations include:

1. **Gaussian masking**: Replace bounded uniform masking with discrete Gaussian sampling over a wider range.
2. **Masking amplification**: Have each party sample $y_i$ from wider ranges and use rejection sampling to bound the final $z$.
3. **Hybrid approaches**: Combine QTD's efficient response aggregation with a garbled-circuit rejection sampling step.

### 10.3 Malicious Security Extension

A complete simulation-based TS-UF security proof, including a simulator for corrupted parties' views, remains future work. This requires careful analysis of the masking distribution and its interaction with the underlying Dilithium3 security proof.

### 10.4 Dynamic DKG

The current DKG implementation derives the full secret key from a jointly generated seed and then applies Shamir sharing. A fully decentralized DKG where no single party ever holds the complete key is planned for the next implementation iteration. This is critical for production deployment, as the current seed-based approach requires a trusted dealer during the DKG phase.

### 10.5 Sharding

The Ministry of Works (Gongbu) provides the infrastructure for shard management, but the actual sharding protocol - including cross-shard communication, state partitioning, and shard-specific consensus - is not yet implemented. We envision each shard having its own Three-Chamber structure with shared security from the main chain's Seal Chamber.

---

## 11. Conclusion

We have presented Stardust Consensus, a post-quantum blockchain consensus protocol that achieves instant finality through the novel combination of a Three-Chamber separation-of-powers architecture and QTD threshold signing over Dilithium3. The key innovation is the decomposition of consensus authority into three mutually constraining chambers - Executive (proposal), Review (attestation with veto), and Seal (threshold finalization) - each with distinct roles and the power to block the process, preventing any single entity from unilaterally controlling consensus.

The Seal Chamber's 2-of-3 QTD threshold signing produces a single 3,293-byte Dilithium3 signature that serves as a constant-size finality proof, verifiable by light clients with a single signature check. This reduces finality latency from approximately 13 minutes (Casper FFG) to under 6 seconds, while providing post-quantum security through Dilithium3 (FIPS 204).

The protocol is implemented in Go with comprehensive testing (43 QTD unit tests, 28 Stardust integration tests) and supports 200,000 validators through O(log n) proposer selection and O(1) validator lookup. Graceful degradation to Casper FFG ensures liveness when QTD is unavailable.

We have provided an honest analysis of the protocol's limitations, including the semi-honest security model, the masking distribution trade-off, and the need for a fully decentralized DKG. These are active areas of research, and we believe that the Three-Chamber architecture provides a robust foundation for future improvements in security, scalability, and functionality.

---

## References

[1] Buterin, V., & Griffith, V. (2017). Casper the Friendly Finality Gadget. *arXiv preprint arXiv:1710.09437*.

[2] Kwon, J., & Buchman, E. (2016). Tendermint: Byzantine Fault Tolerance in the Age of Blockchains. *Cosmos Whitepaper*.

[3] Yin, M., Malkhi, D., Reiter, M. K., Gueta, G., & Abraham, I. (2019). HotStuff: BFT Consensus with Linearity and Responsiveness. *ACM PODC 2019*, 347-356.

[4] Gilad, Y., Hemo, R., Micali, S., Vlachos, G., & Zeldovich, N. (2017). Algorand: Scaling Byzantine Agreements for Cryptocurrencies. *ACM SOSP 2017*, 51-68.

[5] Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., & Stehle, D. (2018). CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme. *IACR TCHES*, 2018(1), 238-268.

[6] NIST (2024). FIPS 204: Module-Lattice-Based Digital Signature Standard.

[7] Komlo, C., & Goldberg, I. (2021). FROST: Flexible Round-Optimized Schnorr Threshold Signatures. *SAC 2020*, 34-60.

[8] Boneh, D., Eskandarian, S., Fisch, B., & Hanzlik, L. (2023). A Simple and Efficient Threshold Signature Scheme for Dilithium. *EUROCRYPT 2023*.

[9] Katsumata, S., Yamada, S., & Yamakawa, T. (2024). First Lattice-Based Two-Round Threshold Signature Scheme. *CRYPTO 2024*.

[10] Quantaureum Engineering Team (2026). QTD: A Practical Two-Round Threshold Signing Protocol for CRYSTALS-Dilithium3. *Quantaureum Technical Report*.

[11] Waterland, P. (2016). The Quantum Resistant Ledger. *QRL Whitepaper*.

[12] Lyubashevsky, V. (2012). Lattice Signatures Without Trapdoors. *EUROCRYPT 2012*, 738-755.

[13] Feldman, P. (1987). A Practical Scheme for Non-interactive Verifiable Secret Sharing. *FOCS 1987*, 427-438.

[14] Gennaro, R., Goldfeder, S., & Narayanan, A. (2016). Threshold-Optimal DSA/ECDSA Signatures and an Application to Bitcoin Wallet Security. *ACNS 2016*, 156-174.

[15] Doerner, J., Kondi, Y., Lee, E., & Shelat, A. (2018). Secure Two-Party Threshold ECDSA from ECDSA Assumptions. *IEEE S&P 2018*, 175-192.
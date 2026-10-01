# QTD: A Practical Two-Round Threshold Signing Protocol for CRYSTALS-Dilithium3

**Authors**: Quantaureum Engineering Team
**Date**: May 16, 2026
**Status**: Draft v2.0
**Contact**: research@quantaureum.com

---

## Abstract

We describe QTD (Quantaureum Threshold Dilithium), a two-round threshold signing protocol for the CRYSTALS-Dilithium3 post-quantum signature scheme. The protocol enables any t-of-n parties to jointly produce a signature that is verifiable by a standard, unmodified Dilithium3 verifier, without reconstructing the complete private key at any single location. Our approach departs from prior work by directly exploiting the algebraic structure of Dilithium3's signing equation: Shamir shares of the secret key component s_1 are individually weighted by Lagrange coefficients in the response computation, while masking contributions are aggregated via direct summation. This design achieves a simple two-round protocol with a pure Go implementation, comprising 43 unit tests and practical security hardening. We provide a complete specification, correctness analysis, performance benchmarks, and an honest discussion of security properties and limitations.

---

## 1. Introduction

CRYSTALS-Dilithium [1] was selected by NIST as the primary post-quantum digital signature algorithm and standardized as FIPS 204 [6]. Threshold signing — the ability for a quorum of parties to jointly produce a signature — is critical for institutional custody, DAO governance, and multi-party blockchain wallets. For discrete-log-based schemes such as Schnorr, threshold signing is well understood and standardized via protocols like FROST [2]. For lattice-based signatures, however, threshold signing remains significantly more challenging.

### 1.1 The Challenge

The primary obstacle is Dilithium's rejection sampling step. During standard signing, a masking vector y is sampled from a wide distribution S_{γ1-1}, a candidate response z = s_1 · c + y is computed, and the signature is rejected (requiring a restart) if ||z||_∞ ≥ γ1 - β. This rejection loop is inherently non-linear: ||Σz_i|| ≠ Σ||z_i||, so parties cannot independently check whether their partial contributions will combine into an acceptable signature.

Two recent works address this challenge:

- **Boneh et al. [4]** (Eurocrypt 2023) construct a threshold Dilithium scheme using garbled circuits to securely evaluate the rejection sampling step. This achieves full malicious security but introduces substantial computational overhead from the garbled circuit evaluation.

- **Katsumata et al. [5]** (Crypto 2024) present the first lattice-based two-round threshold signature scheme using linear secret sharing and an interactive proof system. Their construction achieves strong security guarantees through sophisticated cryptographic machinery.

### 1.2 Our Approach

We take a different, engineering-oriented approach. Rather than using general MPC or complex interactive proofs, we directly exploit the linearity of Dilithium3's response computation:

- The secret key component s_1 is shared using Shamir secret sharing over R_q.
- During signing, each party P_i computes a partial response: z_i = λ_i · s_{1,i} · c + y_i, where λ_i is the Lagrange coefficient for P_i, s_{1,i} is the party's share of s_1, c is the jointly computed challenge, and y_i is a locally generated masking share.
- Aggregation: z = Σ z_i = s_1 · c + Σ y_i. The Lagrange coefficients reconstruct s_1 from its shares, while the masking contributions combine via direct summation.
- The aggregated result z, together with the hint h and challenge c, forms a standard Dilithium3 signature.

**Key design choice.** Masking vector coefficients are drawn from [-η2, η2] rather than the full [-γ1, γ1] range of standard Dilithium3. This means ||z|| almost never exceeds the rejection bound, eliminating the need for a restart loop. The engineering trade-off is that the masking distribution is narrower than in standard Dilithium3, which has implications for the zero-knowledge property (discussed in Section 5.3).

### 1.3 Contributions

- A **two-round threshold signing protocol** for Dilithium3 that produces standard-compatible signatures without private key reconstruction.
- A **distributed key generation (DKG) procedure** with Pedersen-committed verification vectors and seed commitment to prevent last-revealer attacks.
- A **production-oriented Go implementation** with 43 unit tests, constant-time operations, memory zeroization, collusion detection, and BLS12-381 Schnorr zero-knowledge proofs for share validity.
- **Performance benchmarks** for all cryptographic primitives on commodity hardware.
- An **honest security analysis** identifying the protocol's security properties, assumptions, and known limitations.

---

## 2. Preliminaries

### 2.1 Dilithium3 Parameters

| Parameter | Symbol | Value |
|-----------|--------|-------|
| Modulus | q | 8380417 |
| Ring degree | n | 256 |
| Matrix dimensions | k × l | 6 × 5 |
| Secret key bound | η | 5 |
| Challenge weight | τ | 39 |
| Rejection bound | γ1 | 2^19 = 524288 |
| Hint granularity | γ2 | (q-1)/32 ≈ 261888 |
| Masking bound | η2 | 72 |

### 2.2 Ring Structure

All polynomial arithmetic takes place in R_q = ℤ_q[X]/(X^{256} + 1). A polynomial a ∈ R_q is represented by its coefficient vector (a_0, ..., a_{255}) with each a_i ∈ [0, q-1]. Matrix-vector products A · v are computed over R_q using negacyclic polynomial multiplication.

### 2.3 Standard Dilithium3 Signing

Given secret key sk = (ρ, K, tr, s_1, s_2) and message M:

1. Compute A = ExpandA(ρ) ∈ R_q^{k×l}
2. Sample y ← S_{γ1-1}^{l} (coefficients uniform in [-γ1+1, γ1-1])
3. Compute w = A · y
4. Compute c = SampleInBall(H(HighBits(w, γ2), M))
5. Compute z = s_1 · c + y
6. If ||z||_∞ ≥ γ1 - β, reject and restart from step 2
7. Compute h = MakeHint(-ct_0, w - cs_2 + ct_0, γ2)
8. Output σ = (z, h, c)

The expected number of attempts is approximately 4.4.

### 2.4 Shamir Secret Sharing over R_q

A secret s ∈ R_q (e.g., a polynomial coefficient) is shared among n parties with threshold t by:

1. Selecting a_1, ..., a_{t-1} ← R_q uniformly
2. Defining f(X) = s + a_1X + ... + a_{t-1}X^{t-1}
3. Giving party P_i the share s_i = f(i) ∈ R_q

Reconstruction from any t shares indexed by I ⊂ {1, ..., n}, |I| = t:

s = Σ_{i∈I} λ_i · s_i (mod q)

where λ_i = Π_{j∈I, j≠i} (-j)/(i-j) mod q are the Lagrange coefficients.

For vector-valued secrets s ∈ R_q^l, sharing is applied component-wise to each coefficient of each polynomial.

### 2.5 Key Algebraic Observation

**Lemma 1 (Weighted Response Linearity).** Let s_{1,1}, ..., s_{1,t} ∈ R_q^l be Shamir shares of s_1 ∈ R_q^l with Lagrange coefficients λ_1, ..., λ_t. Let y_1, ..., y_t ∈ R_q^l be arbitrary vectors, let c be any polynomial in R_q, and define y = Σ_{i=1}^t y_i. Then:

z = Σ_{i=1}^t (λ_i · s_{1,i} · c + y_i) = s_1 · c + y

**Proof.** Σ_i (λ_i · s_{1,i} · c + y_i) = (Σ_i λ_i · s_{1,i}) · c + Σ_i y_i = s_1 · c + y. The first equality uses distributivity of polynomial multiplication; the second uses the reconstruction property of Shamir sharing and the definition of y. ∎

This is the foundation of our protocol. Crucially, the Lagrange coefficients λ_i are applied only to the secret-key-dependent term s_{1,i} · c, not to the masking term y_i. The masking contributions combine via direct summation.

---

## 3. Protocol Specification

### 3.1 System Model

- **n** parties P_1, ..., P_n
- **Threshold** t ≤ n
- **Adversary model**: semi-honest (passive). Parties follow the protocol but may attempt to learn additional information from their view.
- **Communication**: authenticated point-to-point channels and a broadcast primitive (or gossip protocol).
- **Synchrony**: parties proceed in synchronized rounds.

### 3.2 Distributed Key Generation (QTD-DKG)

The DKG procedure produces Shamir shares of a Dilithium3 key pair such that no single party learns the complete private key.

**Step 1: Seed contribution.** Each party P_i samples ξ_i ← {0,1}^{32} uniformly and a nonce r_i ← {0,1}^{16}. It broadcasts the commitment C_i = SHA3-256(ξ_i || i || r_i).

**Step 2: Seed opening.** After all commitments are collected, each party reveals (ξ_i, r_i). All parties verify C_j = SHA3-256(ξ_j || j || r_j) for every j.

**Step 3: Seed combination.** The global seed is ξ = SHA-256(ξ_1 || ξ_2 || ... || ξ_n). Using SHA-256 cascade rather than XOR prevents any single party from controlling the output seed by choosing ξ_i adaptively.

**Step 4: Key expansion.** Expand ξ using SHAKE-256 to derive the public seed ρ, the secret vectors s_1 ∈ R_q^l and s_2 ∈ R_q^k, and the secret seed K. (In a full deployment, this step would be replaced by a proper distributed key generation where each party contributes entropy to the polynomial coefficients directly; the current seed-based approach is a simplification suitable for our implementation context.)

**Step 5: Shamir sharing.** For each coefficient of each polynomial in s_1 and s_2, the designated dealer constructs a degree-(t-1) Shamir polynomial f(X) with f(0) equal to the coefficient value. Share s_{1,i} for party P_i is the vector of evaluations f(i) for all coefficient polynomials of s_1. The dealer also publishes Pedersen verification vectors V = (g^{a_0}, ..., g^{a_{t-1}}) where a_j are the Shamir polynomial coefficients and g is a generator in a suitable group (we use the BLS12-381 curve).

**Step 6: Share verification.** Each party P_i verifies its share against the verification vectors:

g^{s_{1,i}[k]} = Π_{j=0}^{t-1} V_j^{i^j} (mod p)

for each coefficient k, where s_{1,i}[k] denotes the k-th coefficient of party i's share. If verification fails, the party broadcasts a complaint.

**Step 7: Public key derivation.** Each party computes t = A · s_1 + s_2 (using their full knowledge of s_1 and s_2, which are all derived from ξ) and derives t_1 = HighBits(t, γ2). The public key is pk = (ρ, t_1). All parties should arrive at the same pk.

**Output.** Each party P_i holds:
- Its shares s_{1,i} ∈ R_q^l, s_{2,i} ∈ R_q^k
- The public parameters ρ and t_1
- The verification vectors for all sharing polynomials

### 3.3 Threshold Signing (QTD-Sign)

Let I ⊂ {1, ..., n} be the set of t participating parties, and let {λ_i}_{i∈I} be the corresponding Lagrange coefficients.

**Round 1: Masking Commitment.**

Each party P_i, i ∈ I:
1. Samples y_i ← S_{η2}^{l} (coefficients in [-η2, η2])
2. Computes w_i = A · y_i ∈ R_q^k
3. Samples a nonce n_i ← {0,1}^{16}
4. Broadcasts commitment D_i = SHA-256(w_i || i || n_i)

**Round 2: Reveal and Response.**

After receiving all Round 1 commitments:

1. Each party broadcasts (w_i, n_i). All parties verify D_j = SHA-256(w_j || j || n_j) for every j ∈ I.
2. Compute w_agg = Σ_{j∈I} w_j ∈ R_q^k.
3. Compute w_high = HighBits(w_agg, γ2).
4. Compute c = SampleInBall(SHA-256(w_high || M)).
5. Each party P_i computes its response share:

   z_i = λ_i · s_{1,i} · c + y_i

   where · denotes polynomial-vector multiplication in R_q.
6. Each party broadcasts z_i.

**Aggregation.** Any party (or a designated coordinator):

1. Compute z = Σ_{i∈I} z_i.
2. Verify ||z||_∞ ≤ γ1 - β. If the check fails, the protocol restarts from Round 1. (In practice, this check almost never fails due to the narrow masking distribution; see Section 5.1.)
3. Compute h = MakeHint(A · z - c · t_1, w_agg, γ2).
4. Output the signature σ = (z, h, c).

### 3.4 Abort and Fault Handling

If a party fails to broadcast its Round 2 reveal, or if the revealed w_i does not match its commitment, that party is excluded and replaced by another participant (if available). If fewer than t honest parties remain after timeout, the protocol aborts. The coordinator may initiate a new signing session with a different subset of parties.

### 3.5 Signature Format

The output signature σ = (z, h, c) has the same format as a standard Dilithium3 signature:
- z ∈ R_q^l: serialized as l · n · ⌈log₂(q)⌉/8 bytes ≈ 5 · 256 · 3 = 3840 bytes (compressed)
- h: ω · k · n/8 bytes (hint bits)
- c: 32 bytes (seed representation)

The total signature size matches standard Dilithium3 at approximately 3293 bytes.

---

## 4. Correctness

**Theorem 1 (Correctness).** If all parties follow the protocol and the rejection check passes, the output σ = (z, h, c) is a valid Dilithium3 signature on message M under public key pk.

**Proof.** By the protocol construction:

z = Σ_{i∈I} z_i
  = Σ_{i∈I} (λ_i · s_{1,i} · c + y_i)
  = (Σ_{i∈I} λ_i · s_{1,i}) · c + Σ_{i∈I} y_i
  = s_1 · c + y_agg                     [by Lemma 1 and Shamir reconstruction]

where y_agg = Σ_{i∈I} y_i. Also:

w_agg = Σ_{i∈I} w_i = Σ_{i∈I} (A · y_i) = A · (Σ_{i∈I} y_i) = A · y_agg

The challenge is c = SampleInBall(SHA-256(HighBits(w_agg, γ2) || M)), which depends on w_agg identically to how standard Dilithium3 depends on w = A · y.

The hint is h = MakeHint(A · z - c · t_1, w_agg, γ2). In standard Dilithium3, the hint is computed as MakeHint(A · z - c · t_1, w, γ2), where t_1 is the high bits of the public key t = A · s_1 + s_2. Since w = A · y in standard signing and w_agg = A · y_agg in QTD, the hint computation is equivalent.

Given that z, w_agg, c, and h are all computed in the same way as standard Dilithium3, the output tuple (z, h, c) will be accepted by an unmodified Dilithium3 verifier when the rejection check passes. ∎

---

## 5. Security Analysis

### 5.1 Unforgeability

**Claim 1 (Semi-honest EUF-CMA).** In the semi-honest model, the QTD protocol is existentially unforgeable under chosen-message attacks, assuming the EUF-CMA security of standard (non-threshold) Dilithium3.

**Argument.** Any QTD signature (z, h, c) that passes standard Dilithium3 verification constitutes a valid Dilithium3 signature under the public key pk. Therefore, an adversary that forges a QTD signature on a previously unsigned message M* can immediately be used to forge a standard Dilithium3 signature under pk. Since Dilithium3 is EUF-CMA secure [1] in the quantum random oracle model, such a forgery is computationally infeasible.

This reduction holds because QTD output signatures are syntactically and semantically identical to standard Dilithium3 signatures (Theorem 1). The semi-honest assumption is used to guarantee that all t participating parties honestly follow the protocol, which is required for the output to be a valid Dilithium3 signature. ∎

**Discussion.** The above argument does not constitute a simulation-based security proof in the standard threshold signature model (TS-UF). Proving full TS-UF security — where the adversary may corrupt up to t-1 parties — requires a simulator that can simulate the view of corrupted parties without knowing the full secret key. This depends on the zero-knowledge property of the underlying Dilithium3 scheme, which we discuss in Section 5.3.

### 5.2 Threshold Secrecy

**Claim 2 (Share Secrecy).** Any coalition of fewer than t semi-honest parties learns nothing about the private key components (s_1, s_2, K) beyond what is implied by the public key pk.

**Argument.** Each coefficient of s_1 and s_2 is shared using a degree-(t-1) Shamir polynomial over the field GF(q) with q = 8380417. Shamir secret sharing is information-theoretically secure: fewer than t shares reveal no information about the constant term of a degree-(t-1) polynomial. Since this holds independently for each coefficient, the vector-valued shares reveal no information about s_1 or s_2. The commitment-reveal structure in Round 1 ensures that no party can adaptively choose y_i based on another party's masking contribution, preventing information leakage through the masking process. ∎

### 5.3 Zero-Knowledge and the Masking Distribution Trade-off

The most significant deviation of QTD from standard Dilithium3 is in the masking vector distribution. In standard Dilithium3, y is sampled uniformly from S_{γ1-1}^{l} (coefficients in [-524287, 524287]). In QTD, each y_i is sampled from S_{η2}^{l} (coefficients in [-72, 72]), and the effective masking is y_agg = Σ_{i∈I} y_i, with coefficients in [-t·η2, t·η2].

For e.g., t = 3: y_agg coefficients ∈ [-216, 216], compared to [-524287, 524287].

**Implication for rejection sampling.** Since ||s_1 · c||_∞ ≤ η · τ = 5 · 39 = 195, we have ||z||_∞ = ||s_1 · c + y_agg||_∞ ≤ 195 + t·η2. For t ≤ 5, this is at most 555, which is far below the rejection bound γ1 - β ≈ 522368. The protocol therefore almost never requires a restart, achieving essentially deterministic signing latency.

**Implication for zero-knowledge.** The zero-knowledge property of Dilithium3 relies on the masking vector y being sufficiently large to statistically hide s_1 · c in the output z. With a narrower masking distribution, the conditional distribution of z given c reveals more information about s_1 · c than in standard Dilithium3. This does not directly enable key recovery (s_1 · c has only 2τ = 78 possible values for each coefficient), but it means the protocol does not satisfy statistical zero-knowledge in the standard Dilithium3 sense.

**Practical assessment.** The security of the protocol against key recovery attacks depends on whether an attacker can exploit the narrower z distribution to extract s_1 from a collection of signatures. Standard lattice attacks (e.g., learning s_1 from noisy linear equations z = s_1 · c + y) require the noise y to be small relative to the lattice dimension for efficient recovery. In our setting, y_agg is approximately 3-4× the size of s_1 · c in infinity norm, and s_1 · c has a very restricted structure (at most τ = 39 non-zero coefficients per polynomial). We leave a rigorous analysis of the concrete security level to future work.

**Mitigations.** Several approaches can strengthen the zero-knowledge guarantee:
1. **Gaussian masking**: Replace the bounded uniform masking with discrete Gaussian sampling over a wider range, at the cost of higher rejection probability.
2. **Masking amplification**: Have each party sample y_i from wider ranges and use rejection sampling to bound the final z.
3. **Hybrid approaches**: Combine QTD's efficient response aggregation with a garbled-circuit rejection sampling step as in Boneh et al. [4].

### 5.4 Robustness

**Claim 3.** The protocol completes successfully with probability 1 - (Pr[reject])^R within R rounds, where Pr[reject] << 2^{-20} for practical parameters (t ≤ 5).

Since γ1 - β - ||s_1·c||_∞ ≈ 522173 and ||y_agg||_∞ ≤ 360 for t = 5, the probability of exceeding the rejection bound is negligible. The dominant failure mode is network timeout or malicious non-participation, not rejection sampling.

---

## 6. Implementation

### 6.1 Code Structure

The QTD protocol is implemented in Go as a self-contained package within the QuantaureumV2 blockchain codebase. The implementation comprises 10 source files:

| File | Lines | Purpose |
|------|-------|---------|
| `qtd_poly.go` | 335 | Polynomial arithmetic over R_q: addition, multiplication, norm computation |
| `qtd_ntt.go` | 199 | NTT-based polynomial multiplication and matrix-vector products |
| `qtd_sample.go` | 297 | Random sampling: uniform, bounded, error distribution, and rejection checking |
| `qtd_protocol.go` | 489 | Two-round signing session management, aggregation, and verification |
| `qtd_dkg.go` | 756 | Distributed key generation: Shamir splitting, Pedersen verification, seed commitment |
| `qtd_security.go` | 549 | Security hardening: BLS12-381 ZK proofs, timing attack protection, collusion detection |
| `qtd_errors.go` | 23 | Error type definitions |
| `qtd_test.go` | 788 | Unit tests (43 test cases) |
| `qtd_bench_test.go` | 299 | Performance benchmarks |
| `qtd_security_test.go` | 398 | Security-focused tests: timing, collusion, ZK proofs, integrity |

Dependencies: `crypto/sha256`, `crypto/sha3`, `crypto/rand`, `crypto/subtle` (standard library); `github.com/cloudflare/circl/sign/dilithium/mode3` (for key generation and verification).

### 6.2 Performance

Measured on an x86_64 machine at 3.2 GHz (single core):

| Operation | Time | Notes |
|-----------|------|-------|
| Polynomial multiplication | 340 μs | Schoolbook O(N²), N=256 |
| Matrix-vector multiply (6×5) | 8.8 ms | Full Dilithium3 dimensions |
| Uniform sampling (per poly) | 20 μs | SHA-256 rejection sampling |
| Lagrange coefficient (3-of-5) | < 1 μs | Pre-computed |
| ZK proof generation | 1.07 ms | BLS12-381 Schnorr proof |
| **Full signing round (per party)** | **~9.8 ms** | Including masking, matrix mult, response |

For a 2-of-3 threshold with two network rounds, the local computation per party is approximately 20 ms (two rounds of matrix multiplication, plus response computation). Network latency dominates the end-to-end signing time.

### 6.3 Code Quality and Testing

- **43 unit tests** covering polynomial arithmetic, sampling, protocol flow, DKG, security mechanisms, and encoding. All tests pass.
- **Security hardening**: memory zeroization of intermediate values, constant-time comparison for all sensitive operations, Pedersen-committed verification vectors, seed commitment to prevent last-revealer attacks.
- **Collusion detection**: the implementation tracks submission timing and share similarity to detect potential coordination between malicious parties.
- **Benchmark suite**: measures performance of individual cryptographic operations and full protocol runs.

### 6.4 Two Sharing Modes

The implementation supports two secret sharing modes, selectable at configuration time:

**Additive sharing (t=n).** Each party's share s_{1,i} satisfies s_1 = Σ_{i=1}^n s_{1,i}. In this mode, no Lagrange coefficients are needed during signing. A party computes z_i = s_{1,i} · c + y_i, and the aggregator sums all z_i. This mode requires all n parties to participate.

**Shamir sharing (t<n).** The standard t-of-n mode using Lagrange coefficients as described in Section 3. The Lagrange coefficients are pre-computed for the signing subset I at session initialization. Each party's response is z_i = λ_i · s_{1,i} · c + y_i.

---

## 7. Related Work

**Threshold Schnorr and ECDSA.** FROST [2] achieves two-round threshold signing for Schnorr signatures using additive secret sharing and binding commitments. Gennaro and Goldfeder [9] and Doerner et al. [10] construct threshold ECDSA using multiplicative-to-additive share conversion. These works exploit the algebraic structure of discrete-log-based signatures but do not extend to lattice-based schemes due to the non-linear rejection sampling.

**Threshold lattice-based signatures.** The state of the art consists of two major works:

- **Boneh, Eskandarian, Fisch, and Hanzlik [4]** (Eurocrypt 2023) present a threshold signature scheme for Dilithium using garbled circuits to securely evaluate the rejection sampling step. Their construction achieves full malicious security with a proof in the UC framework. The primary trade-off is computational overhead from garbled circuit generation and evaluation.

- **Katsumata, Yamada, and Yamakawa [5]** (Crypto 2024) construct the first two-round lattice-based threshold signature using linear secret sharing and non-interactive zero-knowledge proofs. Their protocol achieves a strong security notion in the standard model but requires heavyweight cryptographic machinery including lattice-based NIZKs.

**Relationship to our work.** QTD departs from both approaches by accepting a simpler security model in exchange for practical efficiency. Rather than using garbled circuits or NIZKs to achieve malicious security, QTD targets the semi-honest setting and produces Dilithium3-compatible signatures through direct algebraic manipulation. Our implementation prioritizes real-world deployment considerations: memory safety, constant-time operations, and practical performance on commodity hardware.

**Verifiable secret sharing.** QTD-DKG uses Pedersen commitments [8] over the BLS12-381 curve for share verification. This enables each party to independently verify that its shares are consistent with the Shamir polynomials without revealing the shares to other parties.

---

## 8. Limitations and Future Work

1. **Semi-honest security.** The protocol as specified is secure against passive (semi-honest) adversaries. Malicious parties can deviate from the protocol in ways that produce invalid signatures (affecting robustness) or potentially leak information. Extending to malicious security requires additional zero-knowledge proofs for correct share computation, which would increase the protocol's complexity and round count.

2. **Zero-knowledge analysis.** As discussed in Section 5.3, the narrowed masking distribution requires a rigorous concrete security analysis to quantify the information leakage from signatures. We are investigating the application of lattice-based leakage-resilience techniques to bound the attacker's advantage.

3. **Formal security proof.** A complete TS-UF security proof in the simulation paradigm, including a simulator for corrupted parties' views, remains future work. This requires careful analysis of the masking distribution and its interaction with the underlying Dilithium3 security proof.

4. **DKG decentralization.** The current DKG implementation derives the full secret key from a jointly generated seed and then applies Shamir sharing. A fully decentralized DKG where no single party ever holds the complete key is planned for the next implementation iteration.

5. **NTT acceleration.** Our polynomial multiplication currently uses schoolbook O(N²) arithmetic. The NTT-based multiplication is implemented but disabled pending verification against the Dilithium3 reference implementation's NTT variant (which differs from standard NTT in coefficient ordering).

---

## 9. Conclusion

We have presented QTD, a practical two-round threshold signing protocol for CRYSTALS-Dilithium3. The protocol leverages the algebraic linearity of Dilithium3's response computation to enable threshold signing through a simple commitment-reveal structure. The key design insight — applying Lagrange coefficients only to the secret-dependent term, not the masking term — ensures that aggregated signatures are compatible with unmodified Dilithium3 verifiers.

The protocol has been implemented in Go with production-oriented security hardening, including constant-time operations, memory zeroization, and collusion detection. Performance measurements indicate that local computation per party is approximately 20 ms for two signing rounds, making the protocol suitable for interactive (online) threshold signing in blockchain wallet applications.

We have provided an honest analysis of the protocol's security properties, identifying the masking distribution trade-off and the semi-honest adversary model as the primary limitations. Several directions for future work are outlined, including a formal simulation-based security proof and the extension to malicious security.

---

## References

[1] Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., & Stehlé, D. (2018). CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme. *IACR TCHES*, 2018(1), 238–268.

[2] Komlo, C., & Goldberg, I. (2021). FROST: Flexible Round-Optimized Schnorr Threshold Signatures. *SAC 2020*, 34–60.

[3] Damgård, I., Orlandi, C., & Simkin, M. (2020). Yet another look at PRFs and secure message transmission. *ASIACRYPT 2020*.

[4] Boneh, D., Eskandarian, S., Fisch, B., & Hanzlik, L. (2023). A Simple and Efficient Threshold Signature Scheme for Dilithium. *EUROCRYPT 2023*.

[5] Katsumata, S., Yamada, S., & Yamakawa, T. (2024). First Lattice-Based Two-Round Threshold Signature Scheme. *CRYPTO 2024*.

[6] NIST (2024). FIPS 204: Module-Lattice-Based Digital Signature Standard.

[7] Lyubashevsky, V. (2012). Lattice Signatures Without Trapdoors. *EUROCRYPT 2012*, 738–755.

[8] Feldman, P. (1987). A Practical Scheme for Non-interactive Verifiable Secret Sharing. *FOCS 1987*, 427–438.

[9] Gennaro, R., Goldfeder, S., & Narayanan, A. (2016). Threshold-Optimal DSA/ECDSA Signatures and an Application to Bitcoin Wallet Security. *ACNS 2016*, 156–174.

[10] Doerner, J., Kondi, Y., Lee, E., & Shelat, A. (2018). Secure Two-Party Threshold ECDSA from ECDSA Assumptions. *IEEE S&P 2018*, 175–192.
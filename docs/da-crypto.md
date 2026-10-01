# DA Cryptography Design Document (P4-3 DoD)

> Scope: Quantaureum quantum blockchain L1 — Data Availability (Danksharding) subsystem
> Version: P4-3 / 2026-07-15
> Review status: **Pending cryptographic advisor review** (P4-3 DoD: "The cryptographic scheme has been reviewed by a cryptographic advisor")
> Related code: `encoding/blob_tx.go`、`encoding/erasure_code.go`、`encoding/gf16.go`、`consensus/da_committee.go`、`consensus/pqvrf.go`、`crypto/`

---

## 1. Why Not BLS12-381 KZG (P4-3 DoD)

### 1.1 Background

Ethereum Danksharding (EIP-4844 + proto-danksharding) uses **KZG10 polynomial commitments on the BLS12-381 curve**, combined with a trusted setup (`powers_of_tau`) to generate a structured reference string (SRS). This scheme is secure under the classical computational model and produces succinct proofs (48-byte commitment, 48-byte opening proof), but it has two problems that fundamentally conflict with Quantaureum's identity:

### 1.2 Fundamental Reasons for Not Adopting It

1. **Not post-quantum secure**: BLS12-381 security relies on the "elliptic curve discrete logarithm problem (ECDLP)" and the "bilinear pairing Diffie-Hellman assumption". Both problem classes can be solved in polynomial time by **Shor's algorithm** under the quantum computational model. Quantaureum is an independent quantum blockchain L1 public chain; the cryptographic contract mandates the full-stack use of Dilithium3 (FIPS 204 / ML-DSA) + Kyber768 (FIPS 203 / ML-KEM), and does not allow mixing in algorithms that Shor can break.
2. **Trusted setup conflicts with decentralization**: KZG SRS requires a multiparty ceremony and carries an "at least one party is honest" trust assumption. Quantaureum's node deployment model (starting with three bootstrap validators, scaling up to a 512-member committee) makes a large ceremony difficult to bear, and conflicts with the principle of "an independent public chain that does not depend on an external trust root".

### 1.3 Current Implementation Downgrade (P0-2, Documented)

`encoding/blob_tx.go` retains the `KZGCommitment [48]byte` and `KZGProof [48]byte` type names to maintain API compatibility, but the actual algorithm has been downgraded:

```go
// encoding/blob_tx.go:102
func KZGCommitmentFromBlob(blob Blob) KZGCommitment {
    var commitment KZGCommitment
    hasher := sha3.NewLegacyKeccak256()
    for i := 0; i < FieldElementsPerBlob; i++ {
        start := i * BytesPerFieldElement
        hasher.Write(blob[start : start+BytesPerFieldElement])
    }
    hash := hasher.Sum(nil)
    copy(commitment[:32], hash)
    return commitment
}
```

- **Commitment**: writes 4096 32-byte field elements sequentially into Keccak256, truncating to the first 32 bytes.
- **Proof**: `ComputeBlobKZGProof = SHA3-256(blob || commitment)`, `ComputeCellProof = SHA3-256(cell || commitment || row || col)`.
- **Type names retained**: `KZGCommitment` / `KZGProof` serve only as an API compatibility layer and **do not constitute a true polynomial commitment**.

### 1.4 Security Impact (Must Be Confirmed by the Advisor)

| Property | True KZG commitment | Current Keccak256 commitment |
|------|------------|--------------------|
| Binding | Computationally unforgeable | Only collision-resistant (birthday bound 2^128) |
| Succinctness | 48-byte proof | Proof = data size, no succinctness |
| Knowledge soundness | Satisfied | Not satisfied: obtained cell+commitment is enough to forge a proof |
| Cell-level polynomial evaluation proof | Supported | **Not supported**: cannot prove that a cell is a valid evaluation of the committed polynomial at a specified point |
| Data availability sampling (DAS) | Cell-level verifiable | Only whole-block integrity is verifiable |

**Conclusion**: until the P0-2 long-term goal (a true post-quantum polynomial commitment) is delivered, the Danksharding config option `DankshardingConfig.Enabled` must remain `false`, and enabling on chains protecting real value is forbidden.

---

## 2. Post-Quantum Commitment Scheme Selection (Long-Term Roadmap)

### 2.1 Candidate Scheme Comparison

| Scheme | Post-quantum | Proof size | Verification cost | Maturity | Notes |
|------|--------|---------|---------|--------|------|
| **A. STARK FRI** | ✅ hash-based | Large (tens of KB ~ hundreds of KB) | High (polynomial interpolation) | High | No trusted setup needed; suited to large blobs, but cell-level proofs are heavy |
| **B. Lattice-based commitment (Kyber-style)** | ✅ lattice-based | Compact (KB-scale) | Medium | Medium | Module-LWE / Module-SIS assumptions; reuses the SRS idea with existing Kyber768 |
| **C. Winternitz hash chain** | ✅ hash-based | Very large (same order as the data) | Low | High | Simple to implement, but loses succinctness; theoretical reference only |

### 2.2 Current State

- **Transitional scheme**: Keccak256 whole-blob hashing commitment (see §1.3), **not a true polynomial commitment**.
- **Why the current one is sufficient**: Quantaureum DAS currently relies on **2D erasure coding + cell-level position-bound hashing proofs**, not single-point polynomial opening. Clients verify availability through the path "collect ≥50% of cells → Lagrange-interpolate to reconstruct → compare against the Keccak256 commitment", which does not require KZG-style single-point proofs.
- **Trade-offs**:
  - ✅ Data integrity: sufficient (collision resistance 2^128).
  - ❌ Cell-level polynomial evaluation proofs: missing (cannot prove a cell is valid without reconstructing the whole blob).
  - ❌ Succinct proofs: missing (proof size ≈ data size).

### 2.3 Selection Recommendation (Pending Advisor Review)

The preference is **Option B (lattice-based commitment)**, for the following reasons:

1. It shares the same origins as Quantaureum's existing Dilithium3 / Kyber768 cryptographic contract, reusing the circl library.
2. Proof size is acceptable (KB-scale), suitable for opening proofs at 32-byte cell granularity.
3. No trusted setup needed, consistent with the decentralization principle.

**Questions pending review**: the concrete construction of lattice-based polynomial commitment opening proofs at 4096 evaluation points, the aggregation strategy, and the coupling point with the existing 2D erasure coding.

---

## 3. Erasure Coding Scheme (P0-1)

### 3.1 Field Selection: GF(2^16) Instead of GF(2^8)

`encoding/gf16.go` implements GF(2^16) arithmetic:

- **Irreducible polynomial**: `x^16 + x^12 + x^3 + x + 1 = 0x1100B`
- **Generator**: `x = 2`
- **Multiplicative group order**: `2^16 - 1 = 65535`
- **Lookup table structure**: `gf16Exp[2*65535]` (doubled anti-log table, avoiding modular multiplication) + `gf16Log[65536]` (log table)
- **Initialization self-check**: `gf16Exp[65534] != 1`, ensuring the generator is primitive (otherwise it panics and requires cryptographer involvement)

**Why not GF(2^8)**:

- GF(2^8) has field size 256, so the maximum number of non-zero evaluation points is 255.
- Quantaureum `CellsPerBlob = 4096`, and after 2D extension `CellsPerBlobExtended = 8192`, far exceeding 255.
- Historical BUG: the original `solveVandermonde` used GF(2^8), overflowing when evaluation points ≥ 255 (`erasure_code.go:286` still retains the error path as legacy reference).

**Why GF(2^16) is sufficient**:

- Field size 65536 > any evaluation point combination of `MaxBlobColumnsExt(12) × CellsPerBlobExtended(8192)`.
- `MaxBlobColumns(6) × 2 = 12` column extension is far smaller than 65535, leaving ample freedom for 2D extension.

### 3.2 1D Extension (Row Direction)

`ExtendBlob1D` (`erasure_code.go:117`):

- Original cells: `P(1), P(2), ..., P(n)`, n = 4096, positions 0..n-1.
- Parity cells: `P(n+1), ..., P(2n)`, positions n..2n-1.
- **Systematic encoding**: the original data appears verbatim in the codeword.
- Algorithm: Lagrange interpolation, precomputing `denom[j] = Π_{i≠j}(x_j − x_i)`, and for each parity point `y` computing `P(y) = Σ_j cells[j] · L_j(y)`.
- Complexity: O(n²) precomputation + O(n²) evaluation.
- **Each 32-byte cell is treated as 16 big-endian uint16 elements**, and the polynomial is evaluated independently at each element position.

### 3.3 2D Extension (Column Direction)

`ExtendBlobs2D` (`erasure_code.go:347`):

- Original columns → evaluation points `1..n` (n ≤ 6).
- Parity columns → evaluation points `n+1..MaxBlobColumnsExt(12)`.
- The column count is small (n ≤ 6), so O(n²) Lagrange precomputation is negligible.
- Per-row parity cell formula: `parity[row] = Σ_j matrix[j][row] · w_j`, where the weights `w_j` are precomputed once per parity column.

### 3.4 Cell Recovery

`RecoverBlob1D` (`erasure_code.go:176`):

- Any n of the 2n cells can reconstruct the original blob.
- Fast path: all original cells available → direct copy.
- Slow path: Lagrange interpolation, precomputing `denom` from the available point set and evaluating `P(y)` for missing points.
- 2D recovery `RecoverBlobs2D`: the column direction requires ≥ originalCount columns available, and the row direction requires ≥ CellsPerBlob rows available, recovering column by column via 1D recovery.

**DAS capacity**: any 50% of cells can reconstruct the complete blob (a property of 2D erasure coding).

---

## 4. Aggregate Signature Scheme (P0-3)

### 4.1 Dual-Mode Design

`BuildAggregateAttestation` (`da_committee.go:629`) in `consensus/da_committee.go` implements two modes:

| Mode | Trigger condition | Signature count | Verification method |
|------|---------|--------|---------|
| **QTD threshold mode (preferred)** | `thresholdSigner != nil && IsThresholdMode() == true` | 1 | Group public key verifies `thresholdMessageForSlot` |
| **Multi-signature transitional mode (fallback)** | QTD not configured, or aggregation failed and signature count ≤ 64 | ≤ 64 | Individual Dilithium3 verification |

### 4.2 Why Threshold Signing Is Mandatory

- DA committee size: `DACommitteeSize = 512` (`da_committee.go:20`).
- Dilithium3 signature size: 3293 bytes each (cryptographic contract).
- Full multi-signature volume: `512 × 3293 ≈ 1.6 MB`, **unacceptable** (both block payload and verification time explode).
- QTD threshold signature: **a constant 1 aggregate signature regardless of committee size**.

### 4.3 QTD Threshold Mode Details

- **Aggregate message**: `thresholdMessageForSlot(slot, commitments)` (`da_committee.go:519`), binding slot, blob commitments, and the domain separator `"QauDASAttestV1"`.
- **Partial signature collection**: only witnesses with `Available=true` enter the aggregation; `partialSigs[validatorIndex] = attestation.Signature`.
- **Aggregation call**: `signer.AggregatePartialSignatures(sealers, partialSigs, msg)`.
- **Failure fallback**: on aggregation failure, if the signature count ≤ `DAMaxTransitionSignatures(64)`, it degrades to multi-signature; otherwise, output is refused (returns nil).

### 4.4 Multi-Signature Transitional Mode Boundary

- `DAMaxTransitionSignatures = 64` (`da_committee.go:32`), a hard cap.
- Exceeding 64 refuses aggregate output, mandating QTD enablement.
- The fallback aggregate must still pass `IsSufficient()` (`AvailableCount / TotalCount ≥ 0.6667`, `DAAttestationThreshold`).
- **Security constraint**: `SetAttestationVerifier` must verify that each `DASAttestation.Signature` is a legitimate partial signature of `thresholdMessageForSlot` (fail-closed; without a configured verifier, all witnesses are rejected).

### 4.5 Questions Pending Review

- DKG reconstruction overhead and refresh cadence of QTD threshold signatures under a 512-member committee with a 2/3 threshold.
- Cryptographic consistency proof between partial signature verification (`DAAttestationVerifier`) and threshold aggregation.
- Slashing logic: how validators who submit invalid partial signatures are slashed.

---

## 5. VRF Randomness (P1-12)

### 5.1 PQVRF Construction

`consensus/pqvrf.go` implements a post-quantum VRF based on Dilithium3:

```
π = Dilithium3.Sign(sk, "QUANTAUREUM_PQVRF_V2" || x)
y = SHAKE-256(π, 256 bits)
```

- **Proof size**: `PQVRFProofSize = Dilithium3SignatureSize = 3293` bytes.
- **Output size**: `PQVRFOutputSize = 32` bytes.
- **Domain separator**: `"QUANTAUREUM_PQVRF_V2"`, preventing cross-protocol reuse.

### 5.2 Security Properties (based on Module-LWE + Module-SIS + random oracle model)

1. **Uniqueness**: Dilithium3 deterministic signing (FIPS 204: `r = H(tr || M)`), so the same `(sk, x)` always produces the same `π`, and `y = KDF(π)` is deterministic.
2. **Provability**: anyone can use `pk` to verify that `π` is a legitimate signature over `x`, and thereby verify `y`.
3. **Bias resistance**: no single party can manipulate the output (the output is derived deterministically from the signature).

> ⚠️ **Current state note**: `pqvrf.go:3` notes "PQVRF retained as an implementation; not used in production consensus; the active VRF is in `vrf.go`". This section describes the target state after P1-12 integration; during the transition period RANDAO remains primary.

### 5.3 Application in DA Committee Shuffle

`DACommitteeManager.getShuffleSeed` (`da_committee.go:171`):

- **Preferred**: `BeaconChain.GetRandomness(epoch)` returns the PQVRF output → used as the shuffle seed.
- **Fallback**: when the beacon is not configured or not finalized, falls back to `getRandao(epoch)` (QPOS RANDAO mix).
- **Shuffle algorithm**: `shuffleIndexedValidators` Fisher-Yates + SHA3 PRNG (`da_committee.go:358`), with the seed mixed with the domain separator `"QuantaureumDACommitteeShuffleV1"`.
- **PRNG modulo bias resistance**: `nextInt` uses rejection sampling (`rejectThreshold = (MaxUint64 / max) * max`) to eliminate modulo bias.

### 5.4 Questions Pending Review

- Whether a Dilithium3 signature as VRF satisfies the standard VRF security definitions (uniqueness / provability / unpredictability under malicious keys).
- Whether the output distribution of `SHAKE-256(π)` as KDF is uniform (vs. using `Hash(pk || x || π)`).
- The liveness-safety trade-off of falling back to RANDAO when the beacon is not finalized.

---

## 6. Items Pending Audit (P4-3 DoD)

The following items require the cryptographic advisor to explicitly sign off during the P4-3 review:

### 6.1 Commitment Scheme

- [ ] **Security impact of the Keccak256 commitment not being a polynomial commitment**: explicitly document the degree to which "DAS can only verify whole-block integrity, not cell-level polynomial evaluation" weakens the light-client security model.
- [ ] **Provable security boundary of DAS sampling under the Keccak256 commitment**: formalize the availability guarantee of the current path "sample ≥50% of cells → Lagrange reconstruction → compare against the commitment".
- [ ] **Lattice-based commitment (Option B) selection confirmation**: feasibility of sharing the SRS with Dilithium3 / Kyber768, and the opening proof construction.

### 6.2 Erasure Coding Parameters

- [ ] **GF(2^16) irreducible polynomial `0x1100B`**: confirm primitivity and consistency with the existing implementation (self-check already exists at `gf16.go:57`).
- [ ] **2D extension parameters**: `MaxBlobColumns=6` → `MaxBlobColumnsExt=12`; whether 50% column-direction fault tolerance is sufficient against adversarial network partitions.
- [ ] **Lagrange interpolation numerical stability**: GF(2^16) has no floating point, so it is theoretically stable, but it still needs confirmation that the `denom[j]` precomputation does not produce a zero factor at n=4096.

### 6.3 Threshold Signature Integration

- [ ] **QTD threshold parameters**: committee 512, threshold 2/3, corresponding to the DKG reconstruction overhead and security proof of the threshold signature scheme.
- [ ] **Partial signature verification consistency**: `DAAttestationVerifier` verifying partial signatures vs. aggregation in `AggregatePartialSignatures`; the two cryptographic contracts must align.
- [ ] **Rationale for the 64-cap of multi-signature transitional mode**: the basis for choosing `DAMaxTransitionSignatures = 64` (verification time, block payload, sybil resistance).
- [ ] **Slashing path**: the attributability and slashing evidence construction for invalid partial signatures.

### 6.4 VRF and Randomness

- [ ] **PQVRF security reduction**: a formal security proof of using the Dilithium3 deterministic signature as VRF (uniqueness / provability / unpredictability).
- [ ] **SHAKE-256 KDF output distribution**: confirm that `y = SHAKE-256(π)` is uniformly distributed under the random oracle model.
- [ ] **Liveness-safety boundary of the RANDAO fallback**: quantify the bias-resistance loss when falling back to RANDAO while the beacon is not finalized.

### 6.5 Cross-Layer Consistency

- [ ] **Domain separator review**: the three domain separators `"QauDASAttestV1"`, `"QUANTAUREUM_PQVRF_V2"`, and `"QuantaureumDACommitteeShuffleV1"` have no conflicts and no cross-protocol reuse.
- [ ] **Constant-time comparison**: `VerifyBlobKZGProof` / `VerifyCellProof` use `subtle.ConstantTimeCompare`; confirm there is no side channel.
- [ ] **Mandatory audit that `DankshardingConfig.Enabled` defaults to false**: before the P0-2 long-term goal is delivered, no mainnet configuration may enable it.

---

## 7. Change Log

| Date | Version | Change |
|------|------|------|
| 2026-07-15 | P4-3 | Initial version. Summarizes the P0-1 (erasure coding), P0-2 (commitment downgrade), P0-3 (threshold signature), and P1-12 (PQVRF) cryptographic decisions and submits them for advisor review. |

## 8. References

- Code:
  - `encoding/blob_tx.go` — KZGCommitment/KZGProof types and Keccak256 commitment
  - `encoding/erasure_code.go` — 1D/2D Lagrange extension and recovery, `SparseBlobMatrix`
  - `encoding/gf16.go` — GF(2^16) arithmetic
  - `consensus/da_committee.go` — DA committee, dual-mode aggregate signature, `DAMaxTransitionSignatures`
  - `consensus/pqvrf.go` — PQVRF (Dilithium3 Sign-then-KDF)
  - `crypto/dilithium.go`、`crypto/kyber.go`、`crypto/gmqtd_sign.go` — quantum cryptography primitives
- Standards:
  - FIPS 204 (ML-DSA / Dilithium3)
  - FIPS 203 (ML-KEM / Kyber768)
- Related documents：`docs/WHITEPAPER.md`、`wallet/tss/qtd_paper.md`、`SECURITY.md`
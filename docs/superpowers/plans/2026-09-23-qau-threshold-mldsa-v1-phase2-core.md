# QAU Threshold ML-DSA v1 Phase 2 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the disabled-by-default cryptographic core and deterministic evidence required for the QAU `4-of-6` Threshold ML-DSA-65 research profile without exposing a full private key to any node or coordinator.

**Architecture:** The implementation uses an explicit fixed committee profile, a clean protocol state machine, standard ML-DSA-65 encoding, and authenticated participant-to-participant messages. Work is split into reviewable layers: profile enforcement, arithmetic compatibility, secret-share and commitment primitives, signing preprocessing, online signing, dealerless DKG, reshare, and node orchestration. No phase may claim production security while the algebra and implementation remain unreviewed, and this plan's own work stops at producing a review candidate. The independent cryptographic review itself is an external third-party engagement, not a task in this plan.

**Tech Stack:** Go, SHA3/SHAKE, Cloudflare CIRCL ML-DSA-65 only as the standard interoperability oracle, existing QAU encrypted persistence, existing authenticated P2P transport.

**Spec:** `docs/superpowers/specs/2026-09-23-qau-threshold-mldsa-v1-design.md`

## Global Constraints

- Active signing committees contain exactly six participants with threshold four.
- At most two active participants may be corrupt; the coordinator is untrusted.
- Late joiners do not receive an active-epoch share outside an authenticated future-epoch reshare.
- Final signatures must verify with the ordinary FIPS 204 ML-DSA-65 verifier.
- Node code must never materialize or serialize a complete ML-DSA private key.
- CIRCL may be used as an interoperability oracle but not as a hidden threshold implementation.
- Every signing attempt uses crash-safe single-use state before releasing a response.
- The experimental feature switch remains mandatory and disabled by default.
- Tests, comments, documentation, configuration, and protocol labels committed to git are English only.
- No commit, push, branch creation, or feature-gate removal is part of this plan.

---

### Task 1: Freeze the 4-of-6 Profile

**Files:**
- Create: `wallet/tss/protocol/profile.go`
- Create: `wallet/tss/protocol/profile_test.go`
- Modify: `wallet/tss/protocol/types.go`
- Modify: `wallet/tss/protocol/types_test.go`

**Interfaces:**
- Produces: `TMLDSAV1Profile`, `DefaultTMLDSAV1Profile()`, `ValidateCommittee(CommitteeID) error`, and `ValidateTransition(CommitteeID, CommitteeID) error`.
- Consumes: existing `CommitteeID` and `ThresholdKeyID` values.

- [x] Write failing tests for exactly six unique participants, threshold four, sorted identifiers, late-join rejection, and valid six-to-six committee rotation.
- [x] Run `go test ./wallet/tss/protocol -run 'TestTMLDSAV1Profile' -count=1` and verify the tests fail because the profile API does not exist.
- [x] Implement immutable profile constants and validation without changing generic legacy `CommitteeID` behavior.
- [x] Run the focused tests and require PASS.

### Task 2: Add Standard ML-DSA-65 Compatibility Vectors

**Files:**
- Create: `wallet/tss/protocol/mldsa65/params.go`
- Create: `wallet/tss/protocol/mldsa65/params_test.go`
- Create: `wallet/tss/protocol/mldsa65/interoperability_test.go`

**Interfaces:**
- Produces: fixed ML-DSA-65 parameter constants, encoded-size validation, and deterministic public-key/signature fixtures generated through the public CIRCL API.
- Consumes: `crypto.SignatureAlgorithmMLDSA65` and `crypto.VerifySignatureForAlgorithm`.

- [x] Write failing tests for FIPS 204 dimensions, bounds, encoded sizes, context binding, signature mutation rejection, and deterministic fixture reproduction.
- [x] Run `go test ./wallet/tss/protocol/mldsa65 -count=1` and verify RED.
- [x] Implement only constants, bounds checking, and fixture helpers; do not copy CIRCL internal source.
- [x] Run the package tests and require PASS.

### Task 3: Implement Canonical Ring Arithmetic

**Files:**
- Create: `wallet/tss/protocol/mldsa65/poly.go`
- Create: `wallet/tss/protocol/mldsa65/poly_test.go`
- Create: `wallet/tss/protocol/mldsa65/rounding.go`
- Create: `wallet/tss/protocol/mldsa65/rounding_test.go`
- Create: `wallet/tss/protocol/mldsa65/encoding.go`
- Create: `wallet/tss/protocol/mldsa65/encoding_test.go`

**Interfaces:**
- Produces: fixed-size polynomial and vector types, modular normalization, addition/subtraction, scalar multiplication, power-of-two rounding, decompose, high bits, low bits, hints, and strict canonical encoders.
- Consumes: constants from Task 2.

- [x] Write table-driven failing tests using boundary coefficients and independent slow reference formulas.
- [x] Add standard-signature differential tests against the public CIRCL API where public APIs permit observation.
- [x] Run the focused tests and verify RED.
- [x] Implement minimal constant-shape arithmetic with explicit range checks and no secret-dependent indexing in protocol paths.
- [ ] Run focused tests, race tests, and fuzz seeds; require PASS.

### Task 4: Implement Authenticated 4-of-6 Share Containers

**Files:**
- Create: `wallet/tss/protocol/mldsa65/share.go`
- Create: `wallet/tss/protocol/mldsa65/share_test.go`
- Create: `wallet/tss/protocol/mldsa65/commitment.go`
- Create: `wallet/tss/protocol/mldsa65/commitment_test.go`

**Interfaces:**
- Produces: generation-bound local share containers, participant commitments, share verification, zeroization, and serialization that cannot encode a complete private key.
- Consumes: profile validation and canonical arithmetic.

- [x] Write failing tests for threshold reconstruction in isolated test-only helpers, three-share non-reconstruction, commitment mismatch, generation mismatch, participant mismatch, and zeroization.
- [x] Verify RED.
- [x] Implement share and commitment types with private fields and strict constructors.
- [x] Keep complete-key reconstruction helpers in `_test.go` files only.
- [x] Run focused tests and require PASS.

### Task 5: Define Signing Preprocessing and MPC Boundary

**Files:**
- Create: `wallet/tss/protocol/mldsa65/preprocess.go`
- Create: `wallet/tss/protocol/mldsa65/preprocess_test.go`
- Create: `wallet/tss/protocol/mldsa65/mpc.go`
- Create: `wallet/tss/protocol/mldsa65/mpc_test.go`
- Create: `docs/superpowers/specs/2026-09-23-qau-tmldsa-v1-mpc-security.md`

**Interfaces:**
- Produces: one-time preprocessing records, authenticated opening operations, complaint evidence, and an explicit interface for secure rounding, norm checks, hint generation, and challenge derivation.
- Consumes: crash-safe session IDs, share containers, and canonical arithmetic.

- [x] Write the security document with the exact corruption model, leakage surface, abort semantics, preprocessing assumptions, and simulator obligations.
- [x] Write failing tests proving preprocessing cannot be reused, coordinator views exclude long-term shares, and malformed openings burn the session.
- [x] Verify RED.
- [x] Implement the smallest state and message layer needed to represent the reviewed MPC operations.
- [x] Do not implement a placeholder operation that reconstructs secret values at the coordinator.
- [x] Run focused tests and require PASS.

### Task 6: Implement Online Threshold Signing

Progress note: standard signature parsing, assembly, and ordinary verification
are implemented. Threshold response generation remains blocked on the secure
MPC operations defined in Task 5.

**Files:**
- Create: `wallet/tss/protocol/mldsa65/sign.go`
- Create: `wallet/tss/protocol/mldsa65/sign_test.go`
- Create: `wallet/tss/protocol/mldsa65/sign_adversarial_test.go`
- Modify: `wallet/tss/protocol/backend.go`

**Interfaces:**
- Produces: a concrete `ThresholdBackend` signing implementation yielding a standard 3309-byte ML-DSA-65 signature.
- Consumes: reviewed preprocessing/MPC operations, transcript binding, and single-use records.

- [ ] Write failing end-to-end tests for four honest signers, each valid four-member subset, malicious coordinator reordering, duplicate responses, participant equivocation, abort/retry, context mismatch, and signature mutation.
- [ ] Verify RED before implementation.
- [ ] Implement the protocol state machine without coordinator access to long-term or ephemeral secret shares.
- [ ] Verify every produced signature through `crypto.VerifySignatureForAlgorithm`.
- [ ] Run focused, race, and repeated tests; require PASS.

### Task 7: Implement Dealerless DKG

**Files:**
- Create: `wallet/tss/protocol/mldsa65/dkg.go`
- Create: `wallet/tss/protocol/mldsa65/dkg_test.go`
- Create: `wallet/tss/protocol/mldsa65/dkg_adversarial_test.go`

**Interfaces:**
- Produces: six local shares, one standard ML-DSA-65 public key, a qualified-set digest, and no complete private key.
- Consumes: commitment/share layer, authenticated envelopes, and profile validation.

- [ ] Write failing tests for six-party success, invalid share complaints, missing contribution abort, equivocation evidence, transcript mismatch, restart replay, and deterministic qualified-set agreement.
- [ ] Add a test-only isolated reconstruction oracle solely to compare the distributed public key with standard ML-DSA key equations.
- [ ] Verify RED.
- [ ] Implement contribution, encrypted distribution, verification, complaint, qualification, and durable installation phases.
- [ ] Run focused and adversarial tests; require PASS.

### Task 8: Implement Six-to-Six Reshare

Progress note: the linear four-old-holder to six-new-holder reshare primitive,
strict contribution encoding, encrypted outbound/inbound journals, partial
inbound recovery, fail-closed partial outbound recovery, and cross-layer
restart integration are implemented. Post-commitment random projection,
Reed-Solomon syndrome, constant-link, pairwise masking, and masked-term
commit-reveal primitives are also implemented. A deterministic transcript state
machine, encrypted hash-chained recovery, contribution binding, local share
encoding, four-contribution installation, and exact-epoch durable activation
are implemented. Canonical control messages now route over the authenticated
TSS reshare channel with durable-before-accept application, and the existing
authenticated Kyber768 validator session exports domain-separated pairwise mask
secrets. The participant runner, private contribution delivery, phase retries,
signed abort evidence, six-party activation certificates, exact-epoch routing,
and a six-node crash-recovery acceptance test are implemented. Replacement and
late-join matrix coverage, live multi-process acceptance, and formal review
remain open.

**Files:**
- Create: `wallet/tss/protocol/mldsa65/reshare.go`
- Create: `wallet/tss/protocol/mldsa65/reshare_test.go`
- Modify: `node/tss_reshare_runner.go`
- Modify: `node/tss_reshare_journal.go`

**Interfaces:**
- Produces: generation-preserving, public-key-preserving committee rotation with a new committee version.
- Consumes: existing durable reshare transport and the new v1 share types.

- [ ] Write failing tests for one-through-six member replacements, delayed recipient recovery, old/new share mixing rejection, public-key preservation, failed activation rollback, and late-join admission only through future reshare.
- [ ] Verify RED.
- [x] Implement v1 reshare behind the experimental backend without modifying legacy math.
- [ ] Run focused restart and concurrency tests; require PASS.

### Task 9: Wire P2P and Epoch Activation

**Files:**
- Modify: `node/tmldsa_backend_selection.go`
- Modify: `node/node.go`
- Modify: `node/tss_dkg_coordinator.go`
- Modify: `node/tss_dkg_transport.go`
- Modify: `consensus/provinces.go`
- Modify: `consensus/epoch.go`
- Create: `node/tmldsa_v1_lifecycle_test.go`

**Interfaces:**
- Produces: feature-gated DKG, signing, reshare, restart, and epoch activation for the v1 backend.
- Consumes: Tasks 1 through 8 and existing authenticated transport.

- [ ] Write failing lifecycle tests proving no legacy fallback, exact committee/version binding, durable activation, stale-message rejection, and fail-closed behavior.
- [ ] Verify RED.
- [x] Add minimal orchestration while retaining both experimental environment gates.
- [x] Run node, consensus, and P2P focused tests; require PASS.

### Task 10: Run Six-Node Local Acceptance

**Files:**
- Create: `.local-only/scripts/run-tmldsa-v1-six-node.ps1`
- Create: `.local-only/tmp/qau-tmldsa-v1-phase2-results.md`
- Update: `.local-only/tmp/dkg-finality-closeout-2026-09-23-utc.md`

**Interfaces:**
- Produces: reproducible local evidence only; no tracked operational topology or secrets.

- [ ] Start six isolated local nodes with synthetic devnet-only identities and both experimental gates enabled.
- [ ] Complete dealerless DKG without a complete-key artifact.
- [ ] Finalize blocks using at least two distinct four-node signing subsets.
- [ ] Kill one signer after commit, restart it, and verify the abandoned signing state is burned.
- [ ] Rotate at least two committee members through epoch reshare while preserving the group public key.
- [ ] Start a late node and verify it cannot sign until selected into a later reshare.
- [ ] Verify final signatures with the ordinary ML-DSA-65 verifier.
- [x] Record exact commands, hashes, durations, and limitations in the local results report.

### Task 11: Full Verification and Release Boundary

**Files:**
- Update: `docs/superpowers/specs/2026-09-23-qau-threshold-mldsa-v1-design.md`
- Update: `.local-only/tmp/dkg-finality-closeout-2026-09-23-utc.md`

**Interfaces:**
- Produces: an evidence-backed research-preview readiness verdict, not a production-security claim.

- [x] Run `go test ./wallet/tss/protocol/... -count=1`.
- [ ] Run `go test ./node ./consensus ./p2p ./wallet/tss/... -count=1`.
- [ ] Run `go test -race` on the new protocol packages and targeted node lifecycle tests.
- [ ] Run `go vet ./node ./consensus ./p2p ./wallet/tss/...`.
- [ ] Run `go build ./...` and the crypto module tests/build separately.
- [ ] Run `git diff --check` and the repository-sensitive-data checks required by `AGENTS.md`.
- [x] Document any remaining proof, audit, side-channel, preprocessing, or rollback-anchor gaps.
- [x] Keep the protocol disabled by default until the operator enables the switch.

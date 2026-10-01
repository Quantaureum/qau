# QAU Threshold ML-DSA v1 Phase 1 Foundation Implementation Plan

**Execution Status:** Complete and verified on 2026-09-23.

> **For agentic workers:** Execute inline in the current checkout. Use test-driven development for every behavior change. Do not dispatch subagents unless the user explicitly authorizes them.

**Goal:** Build the versioned cryptographic and crash-safety foundation required before the experimental threshold ML-DSA signing core can be connected.

**Architecture:** Add explicit signature algorithm identities and dual verification, protocol-neutral threshold types, canonical transcript encoding, and a monotonic single-use state machine. Persist single-use records through an encrypted node journal and prohibit fallback to the legacy secret-bearing signer.

**Tech Stack:** Go 1.26.6, CIRCL 1.6.3, SHA3-256, existing AES-GCM/scrypt helpers, existing P2P and consensus packages.

**Spec:** `docs/superpowers/specs/2026-09-23-qau-threshold-mldsa-v1-design.md`

## Global Constraints

- Continue in the current dirty checkout and preserve unrelated changes.
- Do not create a branch, worktree, commit, or push.
- Public source comments and documentation are English.
- Temporary data stays under `.local-only/`.
- Both experimental gates are required; v1 never falls back to legacy TSS.
- V1 messages never serialize `ScShare`, `S2Share`, or `T0Share`.
- Validation uses `CGO_ENABLED=0` and `.local-only/tmp/go-build-cache`.
- Go binary: `C:/Users/yuant/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.windows-amd64/bin/go.exe`.

---

### Task 1: Add Explicit Signature Algorithms and Dual Verification

**Files:**
- Create: `crypto/signature_algorithm.go`
- Create: `crypto/signature_algorithm_test.go`
- Modify: `crypto/signing_verifier.go`

**Interfaces:**
- Produces: `crypto.SignatureAlgorithm` and `crypto.VerifySignatureForAlgorithm`.
- Preserves: existing `crypto.Verify` behavior for legacy callers.

- [ ] Write `TestSignatureAlgorithmSizes` first. It asserts legacy signature
  size 3293, ML-DSA-65 signature size 3309, public-key size 1952 for both, and
  rejection of unknown algorithms.
- [ ] Run `go test ./... -run TestSignatureAlgorithmSizes -count=1` from
  `crypto`; verify compile failure because the type is undefined.
- [ ] Implement:

```go
type SignatureAlgorithm uint16

const (
	SignatureAlgorithmUnknown          SignatureAlgorithm = 0
	SignatureAlgorithmDilithium3Legacy SignatureAlgorithm = 1
	SignatureAlgorithmMLDSA65          SignatureAlgorithm = 2
)

func (algorithm SignatureAlgorithm) Supported() bool
func (algorithm SignatureAlgorithm) PublicKeySize() int
func (algorithm SignatureAlgorithm) SignatureSize() int
func (algorithm SignatureAlgorithm) String() string
```

- [ ] Write `TestVerifySignatureForAlgorithm` first. Generate a mode3 key and
  an ML-DSA-65 key, sign one message, verify only under the matching algorithm,
  and reject wrong length, zero key, changed message, and context mismatch.
- [ ] Run the focused test and verify compile failure because the verifier is
  undefined.
- [ ] Implement:

```go
func VerifySignatureForAlgorithm(
	algorithm SignatureAlgorithm,
	publicKey, message, context, signature []byte,
) error
```

The function rejects unknown algorithms, exact-length mismatches, and all-zero
keys; uses `mode3.Verify` for legacy and `mldsa65.Verify` for v1; and converts a
verifier panic into a typed error.

- [ ] Add `SigningVerifier.VerifyMessageSignatureForAlgorithm` without changing
  existing transaction verification defaults.
- [ ] Run `go test ./... -count=1` from `crypto` and require PASS.

### Task 2: Define Protocol-Neutral Threshold Identities

**Files:**
- Create: `wallet/tss/protocol/types.go`
- Create: `wallet/tss/protocol/backend.go`
- Create: `wallet/tss/protocol/types_test.go`

**Interfaces:**
- Consumes: `crypto.SignatureAlgorithm`.
- Produces: immutable key, committee, sign, DKG, and reshare request types.

- [ ] Write tests first for `ThresholdKeyID.Validate` and
  `CommitteeID.Validate`. Reject unknown algorithms, generation zero, wrong or
  zero public keys, version zero, unsorted or duplicate participants, and
  thresholds outside `2 <= t <= n`.
- [ ] Run `go test ./wallet/tss/protocol -count=1`; verify RED because the
  package does not exist.
- [ ] Implement:

```go
type ThresholdKeyID struct {
	Algorithm  crypto.SignatureAlgorithm
	Generation uint64
	PublicKey  []byte
}

type CommitteeID struct {
	Version      uint64
	Threshold    uint32
	Participants []uint32
}

type SigningDomain uint16
```

Add `Validate`, `Clone`, and canonical digest methods. Clone slices at all
public API boundaries.

- [ ] Define typed `SignRequest`, `SigningMessage`, `SigningAction`,
  `DKGRequest`, `DKGMessage`, `DKGAction`, `ReshareRequest`, `ReshareMessage`,
  and `ReshareAction`.
- [ ] Define `ThresholdBackend` with algorithm, public key, sign, DKG, reshare,
  and verify methods from the design.
- [ ] Run `go test ./wallet/tss/protocol -count=1` and require PASS.

### Task 3: Implement Canonical Transcripts and Versioned Envelopes

**Files:**
- Create: `wallet/tss/protocol/transcript.go`
- Create: `wallet/tss/protocol/transcript_test.go`
- Create: `wallet/tss/protocol/envelope.go`
- Create: `wallet/tss/protocol/envelope_test.go`

**Interfaces:**
- Consumes: Task 2 identities.
- Produces: `SigningSessionID`, canonical envelope encoding, and bounded decode.

- [ ] Write transcript tests first. Assert deterministic IDs and ID changes for
  chain, generation, committee, epoch, slot, domain, message, participant, and
  attempt nonce changes. Reject unsorted participants.
- [ ] Run the focused test and verify RED.
- [ ] Implement fixed-width big-endian and length-prefixed encoding:

```go
func SigningSessionID(request SignRequest) ([32]byte, error)
```

Hash with SHA3-256 and prefix `QAU-TMLDSA65-V1-SIGN`.

- [ ] Write envelope round-trip and rejection tests first. Cover unknown
  version, unknown algorithm, oversized payload, trailing bytes, zero session,
  sender zero, and non-canonical re-encoding.
- [ ] Implement `ThresholdEnvelope`, `EncodeEnvelope`, and `DecodeEnvelope` with
  a 1 MiB maximum and bounded field lengths before allocation.
- [ ] Run `go test ./wallet/tss/protocol -count=1` and require PASS.

### Task 4: Implement the Single-Use State Machine

**Files:**
- Create: `wallet/tss/protocol/single_use.go`
- Create: `wallet/tss/protocol/single_use_test.go`

**Interfaces:**
- Consumes: signing session IDs.
- Produces: monotonic state transitions and durable record payloads.

- [ ] Write table-driven tests first for `Created -> Prepared -> Committed ->
  Responded -> Finalized`, all legal transitions to `Burned`, and rejection of
  every backward or repeated response transition.
- [ ] Add concurrency test asserting two simultaneous response attempts produce
  exactly one successful transition.
- [ ] Run focused tests and verify RED.
- [ ] Implement:

```go
type SingleUseState uint8

const (
	SingleUseCreated SingleUseState = iota
	SingleUsePrepared
	SingleUseCommitted
	SingleUseResponded
	SingleUseFinalized
	SingleUseBurned
)

type SingleUseRecord struct {
	SessionID      [32]byte
	State          SingleUseState
	Sequence       uint64
	PreviousHash   [32]byte
	CommitmentHash [32]byte
	ResponseHash   [32]byte
}

func (record SingleUseRecord) Transition(next SingleUseState, payload []byte) (SingleUseRecord, error)
```

The response transition requires non-empty response bytes and records their
SHA3-256 digest. A committed record restored without a durable response can
only transition to burned.
- [ ] Run `go test ./wallet/tss/protocol -count=1` and require PASS.

### Task 5: Persist Encrypted Single-Use Records

**Files:**
- Create: `node/tmldsa_signing_journal.go`
- Create: `node/tmldsa_signing_journal_test.go`
- Modify: `node/config.go`

**Interfaces:**
- Consumes: `protocol.SingleUseRecord` and existing TSS password helpers.
- Produces: atomic encrypted load/store and chain-head validation.

- [ ] Write tests first for prepared-record round trip, atomic update,
  conflicting overwrite rejection, broken previous hash, sequence rollback,
  metadata mismatch, and corrupt ciphertext.
- [ ] Add restart tests: prepared may load; committed without response loads as
  burned; responded cannot transition to another response.
- [ ] Run focused node tests and verify RED.
- [ ] Implement journal location:

```text
<TSSKeyShareFile>.tmldsa-v1/sessions/<session-id>.enc
<TSSKeyShareFile>.tmldsa-v1/ledger/head.enc
```

Use `tss.EncryptSingleShareBlob`, `tss.DecryptSingleShareBlob`, file mode 0600,
same-directory temporary files, `Sync`, close, and rename. Serialize writes with
the existing `tssPersistMu`.
- [ ] On load, reject a record behind an available head. Document that complete
  machine rollback remains outside local-only detection.
- [ ] Run `go test ./node -run TestTMLDSASigningJournal -count=1` and require
  PASS.

### Task 6: Add Experimental Gates and No-Fallback Selection

**Files:**
- Modify: `node/config.go`
- Create: `node/tmldsa_backend_selection.go`
- Create: `node/tmldsa_backend_selection_test.go`

**Interfaces:**
- Produces: `experimentalTMLDSAV1Enabled()` and strict backend selection.

- [ ] Write tests first covering the enable switch on and off. Only an enabled
  switch may select v1. A v1 key generation with missing backend must return an
  error and must never select the legacy distributed signer.
- [ ] Run focused tests and verify RED.
- [ ] Implement the exact gate:

```text
QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1=1
```

- [ ] Implement backend selection keyed by explicit signature algorithm and
  generation. Keep current legacy behavior unchanged for legacy generations.
- [ ] Run focused node tests and require PASS.

### Task 7: Phase 1 Integration and Regression Verification

**Files:**
- Create: `node/tmldsa_phase1_integration_test.go`
- Modify only if required by tests: `node/node.go`

**Interfaces:**
- Consumes: Tasks 1 through 6.
- Produces: a tested disabled-by-default foundation for the Phase 2 cryptographic core.

- [ ] Write an integration test that creates an ML-DSA-65 key, constructs a
  versioned `ThresholdKeyID`, derives a signing session, persists prepared and
  committed records, simulates restart, burns the committed record, and verifies
  an ordinary ML-DSA-65 signature through the versioned verifier.
- [ ] Assert that no legacy distributed signer method is invoked for the v1 key.
- [ ] Run the integration test and verify RED before adding any required wiring.
- [ ] Add only the minimal node wiring needed to load the journal and expose the
  selected backend state. Do not add threshold signing math in Phase 1.
- [ ] Run focused tests:

```powershell
go test ./wallet/tss/protocol -count=1
go test ./node -run 'TestTMLDSA|TestExperimentalTMLDSA' -count=1
```

- [ ] Run crypto module tests from `crypto`:

```powershell
go test ./... -count=1
```

- [ ] Run affected package validation from the repository root:

```powershell
go test ./node ./consensus ./wallet/tss/... -count=1
go vet ./node ./consensus ./wallet/tss/...
go build ./...
git diff --check
```

- [ ] Record exact commands and results in
  `.local-only/tmp/qau-tmldsa-v1-phase1-results.md`.

## Phase 2 Entry Gate

Do not implement threshold signing equations, dealerless ML-DSA key generation,
or v1 reshare math until Phase 1 passes. Phase 2 must begin with a separate plan
that freezes the clean-room algebra, deterministic interoperability vectors,
small-committee security assumptions, and legal review of the selected public
construction.

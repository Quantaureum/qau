# QAU Threshold Dilithium3 v1 Implementation Plan (Superseded After Task 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents require explicit user authorization. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a disabled-by-default dealerless four-of-six threshold-finality backend that produces ordinary 3293-byte CIRCL mode3 signatures without reconstructing the group private key.

**Architecture:** Keep the legacy Dilithium3 verification format and add a separate threshold-protocol identity. Reuse algorithm-neutral transcript, persistence, P2P, reshare, and epoch machinery while implementing a new `wallet/tss/protocol/dilithium3v1` cryptographic backend. Cryptographic research gates precede code for commitments, distributed `Power2Round`, preprocessing, and non-linear signing MPC.

**Tech Stack:** Go 1.26.6, Cloudflare CIRCL 1.6.3 mode3, SHA3/SHAKE, existing authenticated P2P transport, existing AES-GCM/scrypt persistence, existing QPOS epoch and QTD finality machinery.

**Spec:** `docs/superpowers/specs/2026-09-24-qau-threshold-dilithium3-v1-design.md`

> Tasks 1-4 remain completed history. Tasks 5 onward are superseded by
> `2026-09-24-qau-dilithium3-v1-cnf-rss-dkg.md` after approval of the CNF-RSS
> architecture. Do not execute the Shamir/Pedersen tasks below.

## Global Constraints

- Signature algorithm remains `SignatureAlgorithmDilithium3Legacy`.
- Public key, private-key encoding, and signature sizes remain 1952, 4000, and 3293 bytes.
- Active committees are exactly six participants with threshold four.
- The security target is a malicious coordinator plus at most two malicious participants.
- No production package may reconstruct or serialize the complete group private key.
- No failed v1 operation may fall back to the legacy aggregator-recoverable signer or ML-DSA backend.
- All new tracked comments, tests, configuration, and documentation are English.
- Preserve unrelated dirty changes; do not create a branch, worktree, commit, or push.
- Temporary scripts, traces, vectors containing large generated data, and run reports stay under `.local-only/`.
- Use `.local-only/tmp/go-overlay.json` for root-package validation while the unrelated zero-byte `consensus/qpos_persist_kv.go` remains present.
- Experimental gates remain disabled by default until explicit operational acceptance.
- Each task starts with a failing focused test and ends with focused passing tests before broader validation.

---

### Task 1: Add Explicit Threshold Protocol Identity

**Files:**
- Modify: `wallet/tss/protocol/types.go`
- Modify: `wallet/tss/protocol/backend.go`
- Modify: `wallet/tss/protocol/envelope.go`
- Modify: `wallet/tss/protocol/transcript.go`
- Modify: `wallet/tss/protocol/profile.go`
- Modify: `wallet/tss/protocol/single_use.go`
- Modify: corresponding `*_test.go` files in `wallet/tss/protocol/`

**Interfaces:**
- Produces: `ThresholdProtocol`, `ThresholdProtocolProfile`, and protocol-bound requests, envelopes, transcripts, and single-use records.
- Preserves: `ThresholdKeyID` as algorithm, generation, and public-key identity.

- [x] **Step 1: Write protocol identity tests**

Add tests that reject unknown protocols, Dilithium protocol with ML-DSA algorithm,
ML-DSA protocol with legacy Dilithium algorithm, zero generation, wrong
committee size, threshold other than four, and transcript reuse across protocols.

- [x] **Step 2: Run the focused tests and verify RED**

```powershell
go test ./wallet/tss/protocol -run 'TestThresholdProtocol|TestThresholdEnvelope|TestSigningTranscript|TestSingleUse' -count=1
```

Expected: compile failure because protocol identity fields and validators do not exist.

- [x] **Step 3: Add the protocol types and fixed profiles**

```go
type ThresholdProtocol uint16

const (
    ThresholdProtocolUnknown ThresholdProtocol = iota
    ThresholdProtocolDilithium3V1
    ThresholdProtocolMLDSA65ExperimentalV1
)

type ThresholdProtocolProfile struct {
    Protocol     ThresholdProtocol
    Algorithm    crypto.SignatureAlgorithm
    Participants uint32
    Threshold    uint32
    MaxCorrupt   uint32
}

func Dilithium3V1Profile() ThresholdProtocolProfile
func MLDSA65ExperimentalV1Profile() ThresholdProtocolProfile
func (profile ThresholdProtocolProfile) ValidateCommittee(CommitteeID) error
func (profile ThresholdProtocolProfile) ValidateTransition(CommitteeID, CommitteeID) error
```

The Dilithium profile returns legacy mode3, six participants, threshold four,
and maximum corruption two. Keep compatibility wrappers for existing ML-DSA
tests until their callers are migrated.

- [x] **Step 4: Bind protocol identity everywhere**

Add `Protocol ThresholdProtocol` to `SignRequest`, `DKGRequest`,
`ReshareRequest`, `ThresholdEnvelope`, and `SingleUseRecord`. Include it in all
canonical digests and reject mismatches before dispatching to a backend.

- [x] **Step 5: Replace ML-DSA-specific single-use domains**

Use a generic domain containing the numeric protocol identifier instead of
`QAU-TMLDSA65-V1-SINGLE-USE`. Existing experimental records retain their old
decoder version and are not silently reinterpreted as Dilithium records.

- [x] **Step 6: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol -count=1
```

### Task 2: Add Dilithium v1 Gates and Strict Backend Selection

**Files:**
- Modify: `node/tmldsa_backend_selection.go`
- Modify: `node/tmldsa_backend_selection_test.go`
- Create: `node/threshold_backend_selection.go`
- Create: `node/threshold_backend_selection_test.go`
- Modify: `node/config.go`

**Interfaces:**
- Produces: protocol-aware backend selection with no unsafe fallback.
- Preserves: the existing ML-DSA experimental gates and behavior.

- [x] **Step 1: Write backend matrix tests**

Cover every combination of protocol, algorithm, backend availability, and gate
state. Assert that Dilithium v1 cannot select the old legacy signer merely
because both use `SignatureAlgorithmDilithium3Legacy`.

- [x] **Step 2: Run tests and verify RED**

```powershell
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestThresholdBackendSelection|TestExperimentalTDilithium3' -count=1
```

- [x] **Step 3: Introduce protocol-aware backend kinds**

```go
type thresholdBackendKind uint8

const (
    thresholdBackendUnknown thresholdBackendKind = iota
    thresholdBackendLegacyUnsafe
    thresholdBackendDilithium3V1
    thresholdBackendMLDSA65ExperimentalV1
)

func selectThresholdBackendKind(
    thresholdProtocol protocol.ThresholdProtocol,
    algorithm crypto.SignatureAlgorithm,
    available map[thresholdBackendKind]bool,
) (thresholdBackendKind, error)
```

- [x] **Step 4: Add exact feature gates**

```text
QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1
```

The switch is required. Missing v1 backend returns an error; it never selects
legacy QTD or ML-DSA.

- [x] **Step 5: Run focused tests and require PASS**

```powershell
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestThresholdBackendSelection|TestExperimentalTDilithium3' -count=1
```

### Task 3: Implement Mode3 Compatibility Primitives

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/params.go`
- Create: `wallet/tss/protocol/dilithium3v1/params_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/poly.go`
- Create: `wallet/tss/protocol/dilithium3v1/poly_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/rounding.go`
- Create: `wallet/tss/protocol/dilithium3v1/rounding_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/encoding.go`
- Create: `wallet/tss/protocol/dilithium3v1/encoding_test.go`

**Interfaces:**
- Produces: independently testable mode3 parameters, ring arithmetic, rounding,
  decomposition, hint, norm, and canonical encoding functions.
- Consumes: CIRCL mode3 only as an interoperability oracle.

- [x] **Step 1: Write immutable parameter tests**

Assert `N`, `Q`, `K`, `L`, `Eta`, `Tau`, `Beta`, `Gamma1`, `Gamma2`, `Omega`,
`D`, and exact 1952/4000/3293 encoded sizes against the pinned CIRCL API.

- [x] **Step 2: Write arithmetic and boundary tests**

Use independent formulas for normalization, addition, subtraction, scalar
multiplication, `Power2Round`, `Decompose`, `HighBits`, `LowBits`, `MakeHint`,
`UseHint`, and infinity norm. Include coefficients at `0`, `1`, `Q-1`,
rounding boundaries, and negative representatives.

- [x] **Step 3: Run tests and verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -count=1
```

- [x] **Step 4: Implement fixed-size arithmetic types**

```go
type Coefficient int32
type Poly [256]Coefficient
type VectorL [5]Poly
type VectorK [6]Poly

func Normalize(Coefficient) Coefficient
func Add(Poly, Poly) Poly
func Sub(Poly, Poly) Poly
func ScalarMul(Poly, Coefficient) Poly
func Power2Round(Poly) (high Poly, low Poly)
func Decompose(Poly) (high Poly, low Poly)
func InfinityNorm(Poly) int32
```

Use fixed-bound loops with no data-dependent slice sizing. Do not import the
legacy `wallet/tss/qtd` implementation into the new package.

- [x] **Step 5: Implement strict canonical encoders**

Provide fixed-size encoders and decoders for every public and local-share
component. Reject non-canonical coefficients, trailing bytes, wrong dimensions,
and oversized hints.

- [x] **Step 6: Add reference interoperability vectors**

Generate deterministic non-production mode3 keys and signatures in tests.
Verify parsing, mutation rejection, and final verification through
`crypto.VerifySignatureForAlgorithm`.

- [x] **Step 7: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestParameters|TestPoly|TestRounding|TestEncoding|TestMode3Interop' -count=1
```

### Task 4: Define Local Shares and Protocol-Bound Persistence

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/share.go`
- Create: `wallet/tss/protocol/dilithium3v1/share_encoding.go`
- Create: `wallet/tss/protocol/dilithium3v1/share_test.go`
- Create: `node/threshold_protocol_paths.go`
- Create: `node/threshold_share_store.go`
- Create: `node/threshold_share_store_test.go`
- Modify: `node/tmldsa_persistence_crypto.go`

**Interfaces:**
- Produces: a Dilithium3 v1 `LocalShare` that cannot be mistaken for legacy QTD or ML-DSA state.
- Reuses: existing encryption, scrypt, atomic write, and zeroization helpers.

- [x] **Step 1: Write share validation tests**

Reject zero participant, wrong protocol, wrong algorithm, wrong generation,
non-four-of-six committee, incorrect vector dimensions, zero public key,
transcript mismatch, and malformed encodings.

- [x] **Step 2: Define the share type**

```go
type LocalShare struct {
    Protocol         protocol.ThresholdProtocol
    Key              protocol.ThresholdKeyID
    Committee        protocol.CommitteeID
    ParticipantID    uint32
    ActivationEpoch  uint64
    TranscriptDigest [32]byte
    Rho               [32]byte
    S1Share           VectorL
    S2Share           VectorK
    T0Share           VectorK
}

func (share *LocalShare) Validate() error
func (share *LocalShare) Clone() *LocalShare
func (share *LocalShare) Zeroize()
```

- [x] **Step 3: Add canonical share encoding**

Include explicit magic, format version, protocol, algorithm, generation,
committee digest, participant identifier, transcript digest, and fixed-size
secret vectors. Validate fully before publishing decoded secret data.

- [x] **Step 4: Implement protocol-specific paths**

```text
<TSSKeyShareFile>.threshold-v1/dilithium3-v1/generations/<generation>/shares/<participant>.enc
<TSSKeyShareFile>.threshold-v1/dilithium3-v1/active.enc
<TSSKeyShareFile>.threshold-v1/dilithium3-v1/ledger/head.enc
```

No Dilithium record uses a `.tmldsa-v1` path or `QTMLDSA` magic.

- [x] **Step 5: Implement encrypted atomic load/store**

Use same-directory temporary files, mode `0600`, `Sync`, close, rename, and
serialized writes. Reject rollback behind an available ledger head and reject
metadata mismatch before returning secret data.

- [x] **Step 6: Add restart and corruption tests**

Cover round trip, ciphertext corruption, truncation, wrong password, conflicting
overwrite, active-pointer mismatch, generation rollback, and zeroization on
failed import.

- [x] **Step 7: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestLocalShare' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestThresholdShareStore' -count=1
```

### Task 5: Freeze the Dealerless DKG Commitment Construction

**Files:**
- Create: `docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-dkg-algebra.md`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_commitment.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_commitment_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/complaints.go`
- Create: `wallet/tss/protocol/dilithium3v1/complaints_test.go`

**Interfaces:**
- Produces: a reviewable verifiable-sharing construction over the exact mode3 coefficient domain.
- Blocks: DKG implementation until the commitment field and verification equations are explicit.

- [x] **Step 1: Write the algebra note before implementation**

The note defines the coefficient domain, share field, polynomial degree,
participant coordinates, commitment group or lattice commitment, share
verification equation, coefficient range proof, complaint disclosure, and
binding/hiding assumptions. It explicitly analyzes why the current BLS12-381
Pedersen implementation is or is not valid for arithmetic modulo `Q=8380417`.

- [x] **Step 2: Add an automated incompatibility test for unsafe field reuse**

Construct values whose arithmetic differs between the proposed share field and
the current commitment scalar field. The test must fail if a verifier accepts a
share using inconsistent modular arithmetic.

- [x] **Step 3: Review gate**

Do not implement the selected commitment until the algebra note demonstrates
an injective canonical mapping and matching verification arithmetic. If the
existing Pedersen scheme fails this gate, keep it legacy-only and implement the
construction selected by the note in the new package.

- [ ] **Step 4: Define commitment and complaint interfaces**

```go
type ContributionCommitment struct {
    DealerID        uint32
    SessionID       [32]byte
    Encoded         []byte
    Proof           []byte
}

type PrivateContribution struct {
    DealerID    uint32
    RecipientID uint32
    S1          VectorL
    S2          VectorK
    Blind       []byte
}

type Complaint struct {
    SessionID   [32]byte
    DealerID    uint32
    RecipientID uint32
    Reason      ComplaintReason
    Evidence    []byte
}

func VerifyPrivateContribution(ContributionCommitment, PrivateContribution) error
func VerifyComplaint(Complaint, ContributionCommitment) error
```

- [ ] **Step 5: Write positive and adversarial tests**

Cover valid shares, changed recipient, changed coefficient, wrong session,
wrong dealer, range overflow, duplicate commitment, conflicting commitment,
false complaint, and evidence that attempts to reveal unrelated share data.

- [ ] **Step 6: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKGCommitment|TestDKGComplaint' -count=1
```

### Task 6: Define and Implement Distributed Power2Round

**Files:**
- Create: `docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-power2round.md`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_power2round.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_power2round_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_power2round_vectors_test.go`

**Interfaces:**
- Produces: public `t1` and local authenticated `t0` shares without reconstructing complete `t` or `t0`.
- Consumes: authenticated local shares and the approved DKG commitment construction.

- [ ] **Step 1: Write the exact distributed-rounding specification**

Define coefficient representation, authenticated opening rules, carry and
comparison operations, allowed public outputs, abort evidence, round count,
message bounds, and the simulator view for a coordinator plus two corrupt
participants.

- [ ] **Step 2: Define the state-machine interface**

```go
type Power2RoundSession interface {
    SessionID() [32]byte
    Start(LocalAuthenticatedTShare) (Power2RoundAction, error)
    Handle(Power2RoundMessage) (Power2RoundAction, error)
    PublicT1() (VectorK, bool)
    LocalT0Share() (VectorK, bool)
    Zeroize()
}
```

`Power2RoundAction` contains only authenticated outbound messages, explicit
durable transitions, public evidence, and completion/abort flags.

- [ ] **Step 3: Write reference-vector tests first**

For deterministic test-only secret vectors, compute centralized mode3
`Power2Round` as an oracle. Feed independent shares to six sessions and assert
identical public `t1` plus reconstruction-equivalent `t0` only inside `_test.go`.

- [ ] **Step 4: Write malicious and leakage tests**

Cover changed carry shares, conflicting openings, replay, two corrupt nodes,
malicious coordinator challenge changes, early abort, and transcript inspection
that rejects complete low-bit values at the coordinator boundary.

- [ ] **Step 5: Implement the approved construction**

Keep secret values behind local opaque handles. Public APIs must not return a
complete `t`, complete `t0`, or four local shares. Persist required one-time
authenticated state before releasing its first public message.

- [ ] **Step 6: Run tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDistributedPower2Round' -count=1
```

### Task 7: Implement the Six-Participant DKG State Machine

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/dkg.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_encoding.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/activation_certificate.go`
- Create: `wallet/tss/protocol/dilithium3v1/activation_certificate_test.go`
- Create: `node/tdilithium3_dkg_journal.go`
- Create: `node/tdilithium3_dkg_journal_test.go`

**Interfaces:**
- Produces: a transport-neutral backend implementing `StartDKG` and `HandleDKGMessage`.
- Consumes: Tasks 3 through 6.

- [ ] **Step 1: Write state-transition tests**

Cover `Created -> Commitments -> PrivateShares -> Complaints -> Rounding ->
Installed -> Certified`, with rejection of out-of-order, duplicate, stale,
cross-session, and conflicting messages.

- [ ] **Step 2: Define the backend**

```go
type DKGBackend struct {
    profile protocol.ThresholdProtocolProfile
    localID uint32
    state   DKGState
}

func NewDKGBackend(protocol.DKGRequest, uint32, io.Reader) (*DKGBackend, error)
func (backend *DKGBackend) Start() (protocol.DKGAction, error)
func (backend *DKGBackend) Handle(protocol.DKGMessage) (protocol.DKGAction, error)
func (backend *DKGBackend) LocalShare() (*LocalShare, bool)
```

- [ ] **Step 3: Implement durable-before-send journaling**

Persist local contributions, outbound recipient bytes, inbound verified shares,
complaints, rounding state, installed share digest, and acknowledgement before
reporting each transition complete. Retries resend identical bytes.

- [ ] **Step 4: Require all-six qualification and acknowledgement**

The qualified set must equal the selected six participants. The activation
certificate contains one validator-identity signature from every new member
over protocol, algorithm, generation, committee, epoch, public key, and
transcript digest.

- [ ] **Step 5: Add deterministic six-session tests**

Run six in-memory backends through shuffled message delivery. Assert one public
key, six distinct shares, one transcript digest, valid certificate, and no
complete private-key encoding in messages or journals.

- [ ] **Step 6: Add crash recovery tests**

Restart each participant after every durable phase. Confirm identical resend,
no regenerated contribution, fail-closed conflicting state, and zeroized
aborted material.

- [ ] **Step 7: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKG|TestActivationCertificate' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3DKGJournal' -count=1
```

### Task 8: Freeze Authenticated Preprocessing and Signing MPC

**Files:**
- Create: `docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-signing-mpc.md`
- Create: `wallet/tss/protocol/dilithium3v1/preprocess.go`
- Create: `wallet/tss/protocol/dilithium3v1/preprocess_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/mpc.go`
- Create: `wallet/tss/protocol/dilithium3v1/mpc_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/mpc_arithmetic.go`
- Create: `wallet/tss/protocol/dilithium3v1/mpc_arithmetic_test.go`

**Interfaces:**
- Produces: opaque one-time handles and reviewed secure operations for high bits,
  multiplication, norm checks, rejection, and hint generation.
- Blocks: online signing until its simulator and leakage boundaries are explicit.

- [x] **Step 1: Write the signing MPC specification**

Define preprocessing generation, authentication tags, multiplication triples or
equivalent resources, shared comparison, high-bit extraction, norm comparison,
hint generation, approved openings, rejection leakage, abort evidence, and the
view of a malicious coordinator plus two corrupt participants.

- [x] **Step 2: Define opaque interfaces**

```go
type PreprocessingID [32]byte
type SecretHandle [32]byte

type MPCExecutor interface {
    OpenHighBits(context.Context, MPCSession, SecretHandle) (PublicHighBits, Evidence, error)
    MultiplyPublicChallenge(context.Context, MPCSession, SecretHandle, Challenge) (SecretHandle, Evidence, error)
    CheckNorm(context.Context, MPCSession, SecretHandle, int32) (bool, Evidence, error)
    MakeHints(context.Context, MPCSession, SecretHandle) (HintVector, Evidence, error)
    Burn(MPCSession, SecretHandle) error
}
```

No interface returns a complete secret polynomial or raw authenticated share.

- [x] **Step 3: Write one-time state tests**

Cover available-to-committed-to-burned transitions, concurrent commitment,
restart after commitment, uncertain send, challenge change, participant-set
change, coordinator change, and attempted reuse after rejection.

- [ ] **Step 4: Write active-adversary tests**

Simulate two corrupt participants and a malicious coordinator changing
commitments, challenges, openings, and rejection decisions. Honest nodes either
complete a valid operation or abort with bounded evidence.

- [ ] **Step 5: Implement the reviewed construction**

Persist a record before releasing any commitment. Mark a response consumed and
sync it before transmission. Secret-dependent branches and allocations are
confined to code identified for later side-channel review.

Progress: R51 (`ca3559f`) landed the durable record and single-use state; R52
lands the in-process reference arithmetic core: authenticated bit decomposition,
the reference high-bit formula, the two-sided norm predicate, entry points bound
to a committed one-time record, and the cost envelope pinned by test. Dealerless
mask generation, the active-adversary suite, and the networked executor remain
open (spec obligation 1). R54 adds the executor design note
`2026-09-27-qau-dilithium3-v1-signing-executor.md`, which fixes the network
layer and reports the measured rejection cost (877822 shared multiplications and
1770238 openings per accepted attempt, about `3e9` multiplications per accepted
signature), so the literal rejection loop is gated on the cost-option review in
that note before the subprotocol schedule is fixed. R55 records the P2 necessity
review in the signing MPC note: dropping `P2` from the MPC path is rejected as
unproven, and the resolution is the cited construction's per-party local
rejection on short replicated shares, which removes the carry obligation and
the whole `P1`/`P2` MPC cost. That revision must be authorized and its steps
1 to 4 completed before the executor slices fix their arithmetic.

- [ ] **Step 6: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestPreprocessing|TestMPC' -count=1
```

### Task 9: Implement Four-Participant Mode3 Threshold Signing

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/sign.go`
- Create: `wallet/tss/protocol/dilithium3v1/sign_encoding.go`
- Create: `wallet/tss/protocol/dilithium3v1/sign_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/sign_interop_test.go`
- Create: `node/tdilithium3_signing_journal.go`
- Create: `node/tdilithium3_signing_journal_test.go`

File status: `sign_encoding.go`, `sign_session.go`, `sign_challenge.go`, and the
wallet-side `sign_journal.go` landed before this task. R53 adds `sign.go`,
`sign_test.go`, and `sign_interop_test.go`. The two `node/` files move to the
node-wiring milestone because the exported entry points depend on the networked
executor, which is spec obligation 1 and stays open.

**Interfaces:**
- Produces: `StartSigning`, `HandleSigningMessage`, and ordinary mode3 signature verification.
- Consumes: active local share, exactly four sorted participants, and Task 8 MPC.

- [x] **Step 1: Write request and session tests**

Reject fewer or more than four signers, unsorted or duplicate signers, inactive
committee members, wrong epoch or slot, context bytes for legacy mode3, reused
attempt nonce, and protocol or generation mismatch.

- [x] **Step 2: Define public signature parts**

```go
type SignatureParts struct {
    Challenge Challenge
    Z         VectorL
    Hints     HintVector
}

func AssembleMode3Signature(SignatureParts) ([]byte, error)
func ParseMode3Signature([]byte) (SignatureParts, error)
func AssembleVerifiedSignature(protocol.ThresholdKeyID, []byte, SignatureParts) ([]byte, error)
```

The assembler emits exactly 3293 bytes and invokes the unmodified legacy
verifier before returning.

- [x] **Step 3: Implement the signing state machine**

```text
Created -> Prepared -> Committed -> Challenged -> Responded -> Finalized
                         |              |             |
                         +------------> Burned <------+
```

Bind every transition to chain ID, protocol, algorithm, generation, committee,
epoch, slot, message digest, four signers, coordinator identity, and attempt nonce.

- [x] **Step 4: Implement rejection sampling safely**

Norm or hint rejection burns the entire attempt. Retrying creates a new session
and fresh preprocessing. Never reuse `y`, masks, challenges, or responses.

- [x] **Step 5: Write interoperability tests**

For every one of the 15 four-member subsets of six, sign deterministic test
messages and require a 3293-byte result accepted by
`crypto.VerifySignatureForAlgorithm(SignatureAlgorithmDilithium3Legacy, ...)`.
Mutated challenge, response, hint, message, key, and signer transcript must fail.

- [x] **Step 6: Write threshold and leakage tests**

Assert three participants cannot advance to challenge completion. Inspect every
coordinator-visible message and persisted coordinator record for forbidden
complete `s1`, `s2`, `t0`, `y`, `w`, and 4000-byte private-key encodings.

- [x] **Step 7: Write crash tests**

Crash and restart after prepare, commit, challenge, durable response, response
send, final verification, and rejection. Confirm only prepared-before-send may
resume; all uncertain committed states burn.

- [x] **Step 8: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestThresholdSign|TestMode3SignatureInterop' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3SigningJournal' -count=1
```

Progress: R53 lands the wallet-side reference driver and every wallet-level step
above. `sign.go` sequences the four rounds behind the single-use record and the
three public transcripts (`signingCommitment`, `signingChallenge`,
`signingResponse`) over the `Created -> Prepared -> Committed -> Challenged ->
Responded -> Finalized` state machine, with fail-closed burning of the record
and the journal on every other path. `mpc_arithmetic.go` gains the linear
public-operand arithmetic the rounds need: a public polynomial and a public
matrix multiplied into shared rows, and shared-bit reassembly. The interop test
signs with all fifteen four-member subsets and requires the unmodified mode3
verifier; the rejection tests drive one failing nonce per predicate and require
the aggregate response to stay closed; the restart test requires all four
restart boundaries to burn.

Two limits are deliberate and documented. The driver is in-process reference
scaffolding: it drives all four signers and holds the reconstructed aggregate
secret, so the node-side journal and runner, and the exported
`StartSigning`/`HandleSigningMessage` entry points, wait on the networked
executor (open obligation 1). And the driver prescreens the aggregate nonce in
the clear, because a faithful distributed rejection loop costs about 3400 MPC
attempts per signature at the joint `P1*P2` acceptance rate of 2.9e-4; the
focused run takes about 31 seconds.

### Task 10: Implement Dilithium Six-to-Six Reshare

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/reshare.go`
- Create: `wallet/tss/protocol/dilithium3v1/reshare_encoding.go`
- Create: `wallet/tss/protocol/dilithium3v1/reshare_consistency.go`
- Create: `wallet/tss/protocol/dilithium3v1/reshare_test.go`
- Create: `node/threshold_reshare_journal.go`
- Create: `node/threshold_reshare_runner.go`
- Create: `node/tdilithium3_reshare_test.go`
- Generalize from: `node/tmldsa_reshare_*.go`

**Interfaces:**
- Produces: public-key-preserving committee-version rotation from four old dealers to six new recipients.
- Reuses: generic crash, retry, evidence, and activation patterns without importing ML-DSA field types.

- [ ] **Step 1: Write reshare algebra tests**

For each of the 15 old four-member subsets and representative replacement
patterns from zero through six members, verify weighted-share preservation,
new-share threshold behavior, unchanged public key, and advanced committee version.

- [ ] **Step 2: Define Dilithium reshare types**

```go
type ReshareDealerPlan struct {
    SessionID       [32]byte
    DealerID        uint32
    OldCommittee    protocol.CommitteeID
    NewCommittee    protocol.CommitteeID
    SelectedDealers [4]uint32
}

func NewReshareDealerPlan(*LocalShare, protocol.ReshareRequest, [4]uint32, io.Reader) (*ReshareDealerPlan, error)
func (plan *ReshareDealerPlan) ContributionFor(uint32) (PrivateReshareContribution, error)
func InstallResharedShare(protocol.ReshareRequest, uint32, []PrivateReshareContribution) (*LocalShare, error)
```

- [ ] **Step 3: Generalize engineering state machines**

Extract protocol-neutral encrypted file handling, phase retries, durable inbound
and outbound sets, signed abort evidence, acknowledgement collection, and exact
epoch activation from `tmldsa_reshare_*`. Keep ML-DSA wrappers passing their
existing tests before switching Dilithium callers to the generic layer.

- [ ] **Step 4: Bind all consistency rounds to Dilithium arithmetic**

Replace ML-DSA-specific parameters, share encodings, domain strings, and field
operations. Re-run the commitment compatibility gate from Task 5 for reshare
contributions rather than assuming the old consistency proof remains valid.

- [ ] **Step 5: Add restart and late-recipient tests**

Cover delayed recipient, crash after first durable inbound contribution,
partial outbound recovery, conflicting resend, old/new share mixing, failed
certificate, exact epoch activation, and old-share retirement only after activation.

- [ ] **Step 6: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestReshare' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3Reshare|TestThresholdReshare' -count=1
```

### Task 11: Connect P2P, Epoch Activation, and Finality Verification

**Files:**
- Modify: `p2p/message.go`
- Modify: `p2p/message_validator.go`
- Modify: `p2p/message_test.go`
- Modify: `node/tss_dkg_transport.go`
- Modify: `node/tss_dkg_coordinator.go`
- Modify: `node/node.go`
- Modify: `node/qtd_seal.go`
- Modify: `node/tss_seal_context.go`
- Modify: `consensus/threshold_signer.go`
- Modify: `consensus/provinces.go`
- Modify: `consensus/epoch.go`
- Modify: `consensus/qtd_finality.go`
- Create: `node/tdilithium3_lifecycle_test.go`
- Create: `consensus/tdilithium3_epoch_activation_test.go`

**Interfaces:**
- Produces: authenticated live-network DKG, signing, reshare, historical-key lookup, and exact-epoch activation.
- Preserves: ordinary proposer, attester, transaction, and validator-key behavior.

- [ ] **Step 1: Write protocol-routing tests**

Add P2P tests rejecting unknown protocol, protocol/algorithm mismatch,
cross-round messages, oversized payloads, invalid validator identity signature,
wrong sender, duplicate sequence, and stale generation.

- [ ] **Step 2: Add key descriptors to consensus history**

```go
type ThresholdKeyDescriptor struct {
    Protocol protocol.ThresholdProtocol
    Key      protocol.ThresholdKeyID
    CommitteeVersion uint64
}
```

Store descriptors by activation epoch. Historical verification selects the
explicit algorithm and public key from the descriptor. Existing historical
legacy entries decode to the legacy unsafe protocol only for verification, not signing.

- [ ] **Step 3: Extend the signer interface without ambiguous fallback**

```go
type ThresholdKeySigner interface {
    Protocol() protocol.ThresholdProtocol
    KeyID() protocol.ThresholdKeyID
    SignFinality(protocol.SignRequest) ([]byte, error)
    Verify(protocol.ThresholdKeyID, []byte, []byte) error
    IsThresholdMode() bool
}
```

Update adapters and mocks in the same task. Remove production use of
`AggregatePartialSignatures` for Dilithium v1; its coordinator handles only the
new protocol messages and final verified signature.

- [ ] **Step 4: Wire pre-activation DKG and reshare**

Committee selection schedules work before the activation epoch. The result is
accepted only when election, epoch, six participants, public key, transcript,
generation, committee version, and six-party certificate all match local consensus.

- [ ] **Step 5: Wire finality requests**

Create `protocol.SignRequest` only from the canonical QTD seal context. Select
exactly four responsive members deterministically for the attempt. A retry uses
a fresh nonce and may choose another four-member subset.

- [ ] **Step 6: Add lifecycle tests**

Cover fresh DKG, activation, successful finality, historical verification,
reshare, late join, stale completion, overlapping epoch transition, wrong block
root, three-signer failure, and no unsafe fallback.

- [ ] **Step 7: Run focused tests and require PASS**

```powershell
go test ./p2p -run 'TestThreshold|TestTSS' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3Lifecycle|TestThresholdProtocolRouting' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./consensus -run 'TestTDilithium3|TestQTD.*Historical|TestReshareActivation' -count=1
```

### Task 12: Credit Committee Rewards and Validate Penalty Evidence

**Files:**
- Modify: `consensus/epoch_rewards_census.go`
- Modify: `consensus/epoch_rewards_census_test.go`
- Modify: `consensus/ministry_revenue.go`
- Modify: `consensus/security.go`
- Modify: `consensus/slashing.go`
- Modify: `node/block_producer.go`
- Create: `consensus/committee_rewards_test.go`

**Interfaces:**
- Produces: actual balance credits for verified committee service and evidence-backed penalties.
- Preserves: current proposer and attester reward calculations.

- [ ] **Step 1: Add a configurable committee reward pool**

```go
type CommitteeRewardConfig struct {
    Enabled          bool
    PoolBasisPoints  uint32
    DKGWeight        uint32
    ReshareWeight    uint32
    SigningWeight    uint32
}
```

`PoolBasisPoints` defines additional committee issuance as a fraction of the
existing base epoch issuance and does not reduce proposer or attester rewards.
The mainnet-compatible default remains disabled with zero additional issuance.
Local acceptance enables a nonzero pool explicitly. Governance approval is
required before any production configuration enables it.

- [ ] **Step 2: Record only verifiable service**

Credit DKG or reshare work only from a valid activation certificate. Credit
signing only to the four identities bound into a final verified signature
session. Deduplicate by epoch, service type, session, and participant.

- [ ] **Step 3: Add rewards to actual epoch balances**

Extend `EpochRewards` with committee reward entries consumed by the same balance
crediting path as proposer and attester rewards. Ministry records remain audit
data and are not the source of truth.

- [ ] **Step 4: Separate absence from cryptographic misconduct**

Selected-but-absent validators receive no committee reward. Slash only evidence
that consensus can validate, such as conflicting signed commitments or shares.
Ordinary timeouts use the existing inactivity and downtime policies.

- [ ] **Step 5: Write balance-delta and evidence tests**

Cover selected participant, non-selected validator, selected-but-absent member,
duplicate service record, invalid certificate, conflicting evidence, and
disabled reward configuration.

- [ ] **Step 6: Run focused tests and require PASS**

```powershell
go test -overlay .local-only/tmp/go-overlay.json ./consensus -run 'TestCommitteeReward|TestCommitteePenalty|TestEpochRewards' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestCommitteeRewardDistribution' -count=1
```

### Task 13: Run Six-Node Acceptance and Release Verification

**Files:**
- Create: `.local-only/scripts/run-tdilithium3-v1-six-node.ps1`
- Create: `.local-only/tmp/qau-tdilithium3-v1-results-2026-09-24.md`
- Update: `.local-only/tmp/dkg-finality-closeout-2026-09-23-utc.md`

**Interfaces:**
- Produces: reproducible local evidence and a release-stage verdict.
- Contains: no real infrastructure topology, production addresses, or key material.

- [ ] **Step 1: Start six isolated local nodes**

Use synthetic devnet-only identities, separate data directories and ports, the
two Dilithium experimental gates, and a nonzero devnet committee reward config.

- [ ] **Step 2: Complete fresh dealerless DKG**

Confirm one public key, six local shares, matching transcript and activation
certificate, no 4000-byte group private-key artifact, and exact epoch activation.

- [ ] **Step 3: Exercise all signing subsets**

Across consecutive checkpoints, exercise all 15 four-member subsets. Verify
every final signature is 3293 bytes and accepted by unmodified mode3 verification.

- [ ] **Step 4: Inject crash and network failures**

Crash each protocol role after durable commit and response boundaries. Add
duplication, reordering, delay, bounded partition, coordinator replacement, and
two malicious message senders. Confirm safe completion or evidence-bearing abort.

- [ ] **Step 5: Rotate and admit a late node**

Perform six-to-six reshare with replacements, preserve the public key, activate
at the exact epoch, and prove a late node cannot sign before its future reshare.

- [ ] **Step 6: Verify rewards and history**

Re-query balances to prove committee credits, verify absent members receive no
service reward, and verify pre-rotation finality using historical key descriptors.

- [ ] **Step 7: Run package verification**

```powershell
go test ./wallet/tss/protocol/... -count=1
go test -overlay .local-only/tmp/go-overlay.json ./p2p ./node ./consensus ./core -count=1
go test -race ./wallet/tss/protocol/dilithium3v1 -count=1
go test -race -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3|TestThresholdReshare' -count=1
go vet -overlay .local-only/tmp/go-overlay.json ./wallet/tss/protocol/... ./p2p ./node ./consensus ./core
go build -overlay .local-only/tmp/go-overlay.json ./...
git diff --check
```

- [ ] **Step 8: Run mandatory repository safety checks**

Perform the `AGENTS.md` secret, topology, internal-path, JSON/config full-read,
and real-key-prefix scans. Record commands and zero-hit results only in the
local report.

- [ ] **Step 9: Assign the release stage honestly**

The maximum stage reachable from local evidence alone is `audit-candidate`.
Keep the enable switch required and document unresolved proof, side-channel,
rollback-anchor, and audit findings.

## Execution Checkpoints

- After Tasks 1-4: protocol identity, mode3 compatibility, and persistence review.
- After Tasks 5-7: DKG algebra, distributed rounding, and six-session DKG review.
- After Tasks 8-9: signing MPC and 3293-byte interoperability review.
- After Tasks 10-12: reshare, consensus, and economics review.
- After Task 13: local acceptance evidence and release-stage review.

# QAU Threshold Dilithium3 v1 CNF-RSS DKG Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents require explicit user authorization. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the temporary single-share model with fixed four-of-six CNF replicated shares and make six separate node processes derive, persist, and agree on one ordinary 1952-byte CIRCL mode3 public key without reconstructing a complete private key.

**Architecture:** The six committee positions define all twenty three-member CNF groups. Each participant stores the ten components for groups containing its position. A deterministic group leader privately distributes one seed, all three members derive identical `s1/s2` components and verify one public partial contribution, and all nodes aggregate twenty contributions before standard mode3 `Power2Round` and public-key encoding.

**Tech Stack:** Go 1.26.6, Cloudflare CIRCL 1.6.3 mode3 compatibility, SHA3/SHAKE, existing authenticated P2P transport, existing AES-GCM/scrypt persistence, and existing threshold transcript/envelope types.

**Spec:** `docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`

## Global Constraints

- Signature algorithm remains `SignatureAlgorithmDilithium3Legacy`.
- Threshold protocol remains `ThresholdProtocolDilithium3V1`.
- Active committees are exactly six participants with threshold four.
- The security target is a malicious coordinator plus at most two malicious participants.
- Every CNF group contains exactly three canonical committee positions.
- Every participant stores exactly ten of the twenty components.
- No production package reconstructs or serializes aggregate `s1`, `s2`, `t0`, or a mode3 private key.
- `t0` is transient during public-key assembly and is never persisted.
- The backend remains disabled unless both Dilithium3 v1 experimental gates equal `1`.
- No failure falls back to legacy QTD or ML-DSA experimental code.
- Do not import `wallet/tss/qtd` into `wallet/tss/protocol/dilithium3v1`.
- New tracked comments, tests, configuration, and documentation are English.
- Preserve the dirty checkout; do not create branches, worktrees, commits, or pushes.
- Use `.local-only/tmp/go-overlay.json` for node tests while the unrelated zero-byte consensus file remains present.
- No production-security claim is permitted without verifiable evidence.

---

### Task 1: Implement Canonical CNF Topology

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/rss_topology.go`
- Create: `wallet/tss/protocol/dilithium3v1/rss_topology_test.go`

**Interfaces:**
- Produces: `RSSGroupMask`, canonical group enumeration, ownership checks, leader selection, and active-signer component allocation.
- Consumes: fixed participant count six and threshold four.

- [x] **Step 1: Write topology tests**

Test that `CanonicalRSSGroups()` returns exactly twenty strictly increasing masks, every mask has three set bits, every position owns ten groups, and masks outside the low six bits are rejected.

- [x] **Step 2: Write reconstruction-property tests**

Enumerate every one of the fifteen four-position signer sets. Assert that every signer set intersects every group and that `AllocateRSSGroups(activeMask)` assigns each group exactly once to the lowest active holder.

- [x] **Step 3: Write privacy-property tests**

Enumerate every coalition of zero through three positions and assert that at least one canonical group is disjoint from the coalition.

- [x] **Step 4: Run tests and verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestRSS' -count=1
```

Expected: compile failure because RSS topology types do not exist.

- [x] **Step 5: Implement fixed topology APIs**

```go
type RSSGroupMask uint8

func CanonicalRSSGroups() [20]RSSGroupMask
func (group RSSGroupMask) Validate() error
func (group RSSGroupMask) Contains(position uint8) bool
func (group RSSGroupMask) Leader(attempt uint8) (uint8, error)
func GroupsForPosition(position uint8) ([10]RSSGroupMask, error)
func AllocateRSSGroups(activeMask uint8) ([20]uint8, error)
```

Use fixed-size arrays and fixed-bound loops. `Leader(0)` is the lowest group position; attempts one and two select the remaining positions; later attempts fail.

- [x] **Step 6: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestRSS' -count=1
```

### Task 2: Replace LocalShare with Ten RSS Components

**Files:**
- Modify: `wallet/tss/protocol/dilithium3v1/share.go`
- Modify: `wallet/tss/protocol/dilithium3v1/share_encoding.go`
- Modify: `wallet/tss/protocol/dilithium3v1/share_test.go`
- Modify: `node/threshold_share_store_test.go`

**Interfaces:**
- Consumes: canonical topology from Task 1.
- Produces: version-two RSS local-share records with exact component ownership.

- [x] **Step 1: Rewrite share tests for RSS ownership**

Create a valid position-two share containing the ten masks returned by `GroupsForPosition(2)`. Reject duplicate, missing, foreign, unsorted, zero-digest, wrong-leader, and non-canonical component records.

- [x] **Step 2: Verify rewritten tests fail**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestLocalShare' -count=1
```

Expected: compile failure because `RSSComponent` and `Components` do not exist.

- [x] **Step 3: Define RSS component state**

```go
type RSSComponent struct {
    GroupMask          RSSGroupMask
    DealerPosition     uint8
    ContributionDigest [32]byte
    S1                 VectorL
    S2                 VectorK
}
```

Replace `S1Share`, `S2Share`, and `T0Share` with `ParticipantPosition uint8` and `[10]RSSComponent`. Validation derives the position from the ordered committee and requires exact equality.

- [x] **Step 4: Add encoding version two**

Use magic `QTD3SH02` and version `2`. Encode each component in canonical group order. The old `QTD3SH01` decoder must return a distinct unsupported-version error and must never reinterpret aggregate shares as RSS components.

- [x] **Step 5: Update zeroization and cloning**

Zeroization clears all twenty secret vectors held across the ten local components. Clone must deep-copy public-key and committee slices and must not alias component data.

- [x] **Step 6: Run share and store tests**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestLocalShare' -count=1
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestThresholdShareStore' -count=1
```

### Task 3: Define DKG Session and Public Randomness

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/dkg_session.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_session_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_randomness.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_randomness_test.go`

**Interfaces:**
- Consumes: protocol identities, committee digests, and canonical groups.
- Produces: immutable DKG session identity, ordered randomness transcript, global randomness `R`, and matrix seed `rho`.

- [x] **Step 1: Write session validation tests**

Reject wrong protocol, wrong algorithm, non-four-of-six committee, zero generation, zero activation epoch, zero session nonce, and committee reordering.

- [x] **Step 2: Write randomness tests**

Require exactly one 32-byte contribution from every canonical position. Reject duplicates, omissions, wrong session, and conflicting contributions. Assert deterministic `R` and `rho`, and assert that changing any contribution changes both outputs.

- [x] **Step 3: Verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKGSession|TestDKGRandomness' -count=1
```

- [x] **Step 4: Implement canonical session digests**

```go
type DKGSession struct {
    Protocol        protocol.ThresholdProtocol
    KeyGeneration   uint64
    Committee       protocol.CommitteeID
    ActivationEpoch uint64
    Nonce           [32]byte
}

func (session DKGSession) Validate() error
func (session DKGSession) Digest() ([32]byte, error)
func DeriveDKGRandomness(session DKGSession, contributions [6][32]byte) (global [64]byte, rho [32]byte, err error)
```

Use the exact domains from the CNF-RSS spec and canonical committee order.

- [x] **Step 5: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKGSession|TestDKGRandomness' -count=1
```

### Task 4: Implement Domain-Separated Component Sampling

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/rss_sampler.go`
- Create: `wallet/tss/protocol/dilithium3v1/rss_sampler_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/testdata/rss_vectors.json`

**Interfaces:**
- Consumes: DKG session digest, group mask, leader position, global randomness, and private group seed.
- Produces: deterministic bounded `S1/S2` component vectors and reviewable vectors.

- [x] **Step 1: Write deterministic-vector tests**

Pin one non-production session, group, leader, randomness value, and group seed. Assert the complete SHA3 digest of encoded `S1/S2`, coefficient bounds, and mutation separation for every input field.

- [x] **Step 2: Verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestRSSComponentSampling' -count=1
```

- [x] **Step 3: Implement rejection sampling**

```go
func DeriveRSSComponent(
    sessionDigest [32]byte,
    group RSSGroupMask,
    leaderPosition uint8,
    globalRandomness [64]byte,
    groupSeed [32]byte,
) (s1 VectorL, s2 VectorK, err error)
```

Use SHAKE256 and explicit domain encoding. Sample centered coefficients in `[-Eta,Eta]`, store canonical modulo-q representatives, and reject biased byte values rather than reducing them modulo nine.

- [x] **Step 4: Write vectors and run tests**

Generate the fixture only from the reviewed deterministic test input, then require byte-for-byte stability.

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestRSSComponentSampling' -count=1
```

### Task 5: Implement Mode3 Matrix and Partial Public Contributions

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/ntt.go`
- Create: `wallet/tss/protocol/dilithium3v1/ntt_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/matrix.go`
- Create: `wallet/tss/protocol/dilithium3v1/matrix_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/public_contribution.go`
- Create: `wallet/tss/protocol/dilithium3v1/public_contribution_test.go`

**Interfaces:**
- Consumes: mode3 `rho`, `S1`, and `S2` components.
- Produces: canonical `t_U=A(rho)*s1_U+s2_U mod q`, its digest, and exact interoperability vectors.

- [x] **Step 1: Write NTT and matrix oracle tests**

Use deterministic non-secret vectors and compare polynomial multiplication, matrix expansion, and `A*s1+s2` against a test-only CIRCL-derived oracle. Production code may not import CIRCL internal packages or `wallet/tss/qtd`.

- [x] **Step 2: Verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestNTT|TestMatrix|TestPublicContribution' -count=1
```

- [x] **Step 3: Implement fixed-bound arithmetic**

Implement the required mode3 arithmetic independently from the published
equations and validate it against the test-only oracle. Do not copy CIRCL
internal source and keep all loops fixed-size.

- [x] **Step 4: Implement contribution encoding and digest**

```go
type PublicContribution struct {
    SessionDigest [32]byte
    GroupMask     RSSGroupMask
    DealerPosition uint8
    T             VectorK
}

func NewPublicContribution(...) (PublicContribution, error)
func (contribution PublicContribution) Digest() ([32]byte, error)
func (contribution PublicContribution) MarshalBinary() ([]byte, error)
func UnmarshalPublicContribution([]byte) (PublicContribution, error)
```

- [x] **Step 5: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestNTT|TestMatrix|TestPublicContribution' -count=1
```

### Task 6: Implement Group Seed Messages and Complaints

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/dkg_group.go`
- Create: `wallet/tss/protocol/dilithium3v1/dkg_group_test.go`
- Create: `wallet/tss/protocol/dilithium3v1/complaints.go`
- Create: `wallet/tss/protocol/dilithium3v1/complaints_test.go`

**Interfaces:**
- Consumes: DKG sessions, group topology, component derivation, and public contributions.
- Produces: canonical private group-seed payloads, digest acknowledgements, complaints, and leader replacement.

- [x] **Step 1: Write adversarial message tests**

Reject changed session, committee, group, leader, recipient, attempt, seed, partial contribution, duplicate acknowledgement, false complaint, and evidence unrelated to the disputed group.

- [x] **Step 2: Verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKGGroup|TestDKGComplaint' -count=1
```

- [x] **Step 3: Implement canonical payloads**

Define fixed-version encodings for `GroupSeedMessage`, `ContributionAcknowledgement`, and `Complaint`. Private messages include one seed and recipient; public messages include only digests or a malicious dealer's attributable evidence.

- [x] **Step 4: Implement leader replacement rules**

Attempts zero through two select the group's three positions in ascending order. A valid complaint burns the current attempt and seed. Three failed attempts abort the whole DKG session.

- [x] **Step 5: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestDKGGroup|TestDKGComplaint' -count=1
```

### Task 7: Assemble the Standard Mode3 Public Key

**Files:**
- Create: `wallet/tss/protocol/dilithium3v1/public_key.go`
- Create: `wallet/tss/protocol/dilithium3v1/public_key_test.go`

**Interfaces:**
- Consumes: exactly twenty accepted public contributions and `rho`.
- Produces: one standard 1952-byte public key and a transcript digest without persisted `t0`.

- [x] **Step 1: Write assembly tests**

Reject missing, duplicate, foreign-session, wrong-group, and malformed contributions. Assert that all twenty contributions are required and input ordering does not change the result after canonical sorting.

- [x] **Step 2: Write mode3 interoperability test**

Pin a non-production public-key vector generated by an offline `.local-only`
reference script. Tests consume only `rho`, the twenty public contributions,
and the expected public key; tracked test code never reconstructs aggregate
`s1`, `s2`, `t0`, or a mode3 private key.

- [x] **Step 3: Verify RED**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestAssembleMode3PublicKey' -count=1
```

- [x] **Step 4: Implement assembly**

```go
func AssembleMode3PublicKey(
    rho [32]byte,
    contributions [20]PublicContribution,
) (publicKey [1952]byte, transcriptDigest [32]byte, err error)
```

Aggregate `T`, call `Power2Round`, encode only `t1`, clear transient `t0`, and bind all twenty contribution digests into the transcript.

- [x] **Step 5: Run focused tests and require PASS**

```powershell
go test ./wallet/tss/protocol/dilithium3v1 -run 'TestAssembleMode3PublicKey' -count=1
```

### Task 8: Add Crash-Safe Six-Node DKG Orchestration

**Files:**
- Create: `node/tdilithium3_dkg_journal.go`
- Create: `node/tdilithium3_dkg_journal_test.go`
- Create: `node/tdilithium3_dkg_runner.go`
- Create: `node/tdilithium3_dkg_runner_test.go`
- Create: `node/tdilithium3_dkg_six_node_test.go`
- Create: `node/tdilithium3_dkg_group_round.go`
- Create: `node/tdilithium3_dkg_group_network.go`
- Create: `node/tdilithium3_dkg_group_network_test.go`
- Create: `node/tdilithium3_dkg_group_p2p_test.go`
- Create: `node/tdilithium3_activation_p2p.go`
- Create: `node/tdilithium3_activation_p2p_test.go`
- Modify: `node/tss_dkg_transport.go`
- Modify: `p2p/message.go`
- Modify: `p2p/message_validator.go`

**Interfaces:**
- Consumes: all Task 1-7 cryptographic and persistence APIs.
- Produces: six-process DKG, exact restart, encrypted component installation, and activation acknowledgement.

- [x] **Step 1: Write journal transition tests**

Cover prepared, randomness complete, each group seed persisted, component derived, contribution verified, all groups complete, share installed, and acknowledgement persisted. Reject transition skipping, rollback, cross-session state, and reused group attempts.

- [x] **Step 2: Write six-node happy-path test**

Start six independent runners with authenticated in-memory transports. Require all twenty groups, identical public keys and transcript digests, and exactly ten persisted components per node.

- [x] **Step 3: Write failure-injection tests**

Crash and restart after every durable boundary. Add duplicate, reordered, delayed, missing, and conflicting packets; one malicious leader; two malicious participants; and coordinator replacement.

- [x] **Step 4: Verify RED**

```powershell
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3DKG' -count=1
```

- [x] **Step 5: Implement journal and runner**

Persist before every outbound acknowledgement. Use the protocol-specific share store and never write active state before all twenty contribution records validate.

- [x] **Step 6: Add bounded P2P message routing**

Add explicit Dilithium3 v1 message kinds and size limits. Validate protocol, session, committee, sender identity, group membership, leader attempt, and recipient before queueing.

- [x] **Step 7: Drive every canonical group over the real transport**

Add `node/tdilithium3_dkg_group_round.go`, `node/tdilithium3_dkg_group_network.go`, and `node/tdilithium3_activation_p2p.go`. The driver walks the twenty canonical groups in order over the live P2P transport, keeps early group traffic instead of dropping it, fails closed with `errTDilithium3DKGGroupStalled` when a leader stops making progress, and commits a signed exact-epoch activation certificate. `TestTDilithium3DKGGroupP2PCrossProcess` runs six independent OS processes with real `p2p.Host` instances over TCP and the encrypted transport, and requires identical public keys, transcript digests, and activation certificate digests.

- [x] **Step 8: Run focused and regression tests**

```powershell
go test -overlay .local-only/tmp/go-overlay.json ./node -run 'TestTDilithium3DKG|TestThresholdShareStore|TestThresholdBackendSelection' -count=1
go test ./wallet/tss/protocol/... -count=1
```

## Phase Acceptance

This DKG phase is complete only when:

- six independent runners complete all twenty groups;
- six independent OS processes complete the same run over real TCP with the
  encrypted transport and commit one identical activation certificate;
- each node persists exactly ten components and no aggregate private key;
- all nodes derive the same ordinary 1952-byte mode3 public key;
- missing or conflicting group data prevents activation;
- crashes resume exact persisted attempts without seed reuse;
- an unattributable complaint is refused and a stalled leader fails closed with
  `errTDilithium3DKGGroupStalled` without mutating the journal;
- protocol failure cannot reach legacy QTD or ML-DSA backends;
- the committee roster comes from the finalized-epoch snapshot (option 2 in
  "Finalized-Epoch Validator Snapshot"): two nodes that processed the same blocks
  derive the same roster digest, a restart reproduces it from the bounded
  sidecar, and every missing, unfinalized, size-mismatched, or mismatched roster
  fails closed on `errTDilithium3DKGEpochRosterUnavailable`;
- the sole non-block-derived validator-set mutation entry point fails closed with
  `errConsensusStakeMutationNotBlockDerived`;
- the ceremony is reachable from the running node, not only from tests: the
  session is derived from chain state (roster epoch `ActivationEpoch - 1`,
  committee in roster order with participant IDs `position + 1`, key generation
  equal to the activation epoch, derived nonce), the inbox is installed by the
  ceremony, and `nodeConsensusDKGRunner.RunDistributedDKG` returns the v1 public
  key with no fallback to the legacy group key;
- six independent OS processes driving the production entry point
  `runTDilithium3DKGCeremony` over real TCP derive the same session digest,
  assemble the same 1952-byte public key, and can each resume the persisted
  record afterwards;
- all focused tests and protocol regression tests pass.

### Task 9: Wire the Ceremony into the Production Path

Derived from `2026-09-26-qau-dilithium3-v1-dkg-session-derivation.md`; the
decisions D1 (roster epoch), D2 (committee rule), D3 (derived nonce), D7
(trigger and message-loop gate), D8 (no fallback) and D9 (gating boundary) are
implemented in `node/tdilithium3_dkg_session_derivation.go`,
`node/tdilithium3_dkg_ceremony.go` and `node/tss_reshare_runner.go`.

Acceptance:

- `deriveTDilithium3DKGSession` is deterministic across independent nodes and
  changes with the activation epoch, chain id, genesis block or any roster entry;
- `tdilithium3DKGCommitteeForRoster` yields `[1..6]` for a six-entry roster,
  the local position by address, and fails closed for a missing, wrong-sized or
  foreign roster;
- the roster epoch is `ActivationEpoch - 1` without the finality gate, keeping
  the bootstrap refusal, so the first usable session is at most epoch
  `bootstrap + 2`;
- the local validator key must equal the roster identity key (D6) before any
  message is sent;
- with the gates closed, or on mainnet, `RunDistributedDKG` takes the legacy path
  unchanged; with the gates open the v1 ceremony is entered and a failure returns
  the error with a nil public key.

Threshold signing, same-key RSS reshare, epoch rotation, and rewards are explicitly outside this phase and receive separate plans after this acceptance boundary passes. The DKG also stays experimental until the legacy signing parameter derivation, reshare, and adversarial tests are complete; the finalized-epoch roster source it depends on is implemented (see "Option 2 Implementation" in the CNF-RSS design).

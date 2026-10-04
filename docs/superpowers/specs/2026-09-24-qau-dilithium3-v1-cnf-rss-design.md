# QAU Threshold Dilithium3 v1 CNF-RSS Design

**Status:** Approved architecture; implementation requires a revised plan

**Date:** 2026-09-24

## Purpose

This document replaces the Shamir/Pedersen DKG assumption in the original QAU
Threshold Dilithium3 v1 design with a short replicated secret-sharing
construction specialized to the fixed four-of-six committee.

The target remains unchanged:

- legacy CIRCL Dilithium mode3 verification;
- 1952-byte public keys;
- 3293-byte signatures;
- exactly four signers from an active six-member committee;
- no process, coordinator, journal, or recovery tool reconstructs the complete
  group private key;
- security target of a malicious coordinator plus at most two malicious
  participants;
- disabled-by-default research implementation enabled only by an explicit
  operator switch.

This design is informed by the CNF replicated-sharing construction and DKG
outline in "Efficient Threshold ML-DSA for Groups of up to 6 Signers"
(NIST PQC Conference 2025; USENIX Security 2026). The upstream implementation
is an academic prototype and its test key-generation helper creates all shares
centrally. QAU therefore uses the paper as a construction reference, not as a
production dependency or a source of production-ready DKG code.

## Superseded Decisions

The following earlier decisions are superseded:

1. Long-term secrets are not Shamir shares.
2. DKG correctness is not established through BLS12-381 Pedersen commitments.
3. A participant does not store one aggregate `S1Share`, `S2Share`, and
   `T0Share` tuple.
4. `t0` is not stored or shared by the threshold backend.
5. The Task 5 `ContributionCommitment` interface from the original plan is not
   implemented because it encodes the rejected Shamir/Pedersen architecture.

The BLS12-381 field-incompatibility test remains as a permanent regression
guard. It proves that the rejected construction cannot silently return.

## Fixed CNF Sharing Topology

Let the committee positions be `P = {0,1,2,3,4,5}` in canonical committee
order. Raw validator identifiers are never used as bit positions.

For threshold `T=4` and total participants `N=6`, define one replicated secret
component for every subset `U` of size `N-T+1=3`:

```text
Groups = { U subset P : |U| = 3 }
```

There are exactly `C(6,3)=20` groups. A component belonging to group `U` is
known by every participant in `U` and by no participant outside `U`.

Each participant belongs to exactly `C(5,2)=10` groups and therefore stores ten
secret components. The group identifier is a six-bit mask with exactly three
bits set. Masks are sorted numerically in every canonical encoding.

### Reconstruction Property

Any active set of four participants intersects every three-member group because
`4+3>6`. The active signers can therefore assign every component to at least one
holder and compute one response contribution for every component.

Any coalition of at most three participants misses at least one component. In
the QAU threat model, at most two participants are corrupt, so multiple
all-honest groups remain completely unknown to the adversary.

Threshold signing does not concatenate components or reconstruct a complete
secret. Components are deterministically assigned among the four active
signers, and only aggregate protocol messages leave the holders.

## Canonical Committee Mapping

Every DKG, signing, and reshare transcript contains:

- the ordered six-member `CommitteeID`;
- a mapping from committee position `0..5` to participant identifier;
- the 20 canonical group masks;
- the protocol, key generation, committee version, and activation epoch.

A group mask is meaningless without this exact committee digest. Reordering the
same participant identifiers creates a different committee and invalidates all
group state.

The deterministic leader for a group is initially its lowest committee
position. Leader replacement advances through the other two positions in
ascending order and is transcript-bound. A replacement never reuses the failed
leader's seed or attempt identifier.

## Long-Term Local State

The Dilithium3 v1 local share becomes:

```go
type RSSComponent struct {
    GroupMask         uint8
    DealerPosition    uint8
    ContributionDigest [32]byte
    S1                VectorL
    S2                VectorK
}

type LocalShare struct {
    Protocol          protocol.ThresholdProtocol
    Key               protocol.ThresholdKeyID
    Committee         protocol.CommitteeID
    ParticipantID     uint32
    ParticipantPosition uint8
    ActivationEpoch   uint64
    TranscriptDigest  [32]byte
    Rho               [32]byte
    Components        [10]RSSComponent
}
```

The final implementation may use an unexported fixed-size component array, but
the encoded semantics are fixed by this document.

Each local share must contain exactly the ten canonical groups that include the
participant position. Duplicate, missing, foreign, or incorrectly ordered group
masks are rejected. `S1` and `S2` coefficients are canonical modulo
`q=8380417`. No `T0` component is persisted.

Zeroization clears all component polynomials and any transient group seed.
Public metadata may remain for diagnostics, but a zeroized value cannot be
marshaled or used for signing.

## Dealerless DKG

### Round 0: Session Agreement

All participants agree on the protocol identity, chain identifier, generation,
committee, activation epoch, deadlines, and a fresh DKG session identifier.
Every message is identity-signed and carried in the bounded threshold envelope.
The nonzero chain identifier is included in the session digest before the key
generation, preventing the same committee/nonce transcript from being reused
on another chain. Previously generated experimental records without this
binding are not silently migrated.

The session also requires a nonzero identity-roster digest. This digest commits
the canonical committee order, each participant ID, its validator address, and
its historical legacy Dilithium3 identity public key. A differing identity
roster therefore changes the DKG session digest; older experimental journals
without the roster commitment cannot silently resume under this session.
P2P peer IDs are not committed because connections may change independently of
validator identity.

For every non-activation DKG message, the identity signature covers the
following bytes, in order:

```text
"QAU-THRESHOLD-ENVELOPE-IDENTITY-V1" ||
canonical ThresholdEnvelope encoding through the payload bytes
```

The signed portion includes the envelope magic, version, protocol, algorithm,
message kind, key generation, committee version, session ID, sender ID,
sequence number, payload length, and payload. It excludes the signature-length
field and signature bytes. The signature must be a complete 3293-byte legacy
Dilithium3 identity signature, verified against the sender's historical
committee identity key before a node consumes the message. Structural P2P
validation and an encrypted peer connection do not replace identity
verification. Activation acknowledgements use their separate candidate-bound
`DKGActivationAcknowledgement.SigningBytes` transcript rather than this domain.

### Session Derivation and Wiring

Where a running node obtains the session is specified separately, in
`2026-09-26-qau-dilithium3-v1-dkg-session-derivation.md`. In short: the identity
roster is read from the captured boundary of `ActivationEpoch - 1`, the committee
is that roster in canonical order with participant IDs `position + 1`, the key
generation is the activation epoch, and the session nonce is derived from chain
id, genesis hash, key generation, activation epoch, committee digest and
identity-roster digest. Nothing is random, so a restarted node reconstructs the
identical session and resumes its journal instead of starting a conflicting
attempt. The ceremony runs behind the two default-off experimental gates and is
permanently excluded on mainnet.

### Round 1: Public Randomness

Each participant broadcasts a fresh 32-byte randomness contribution. After all
six valid contributions are available in canonical participant order, every
participant derives:

```text
R = SHAKE256(
    "QAU-TDILITHIUM3-V1-DKG-RANDOMNESS" ||
    session || committeeDigest || contribution_0 || ... || contribution_5
)
```

Missing, conflicting, replayed, or duplicate contributions abort the attempt.
An aborted attempt advances the key generation, which produces a new session
identifier and new contributions; the aborted attempt's randomness and group
seeds are never reused. Crash recovery of an in-flight attempt reuses the same
session identifier and the same per-participant randomness, both of which are
journaled, so a restarted node rejoins the attempt it was already in. See
`2026-09-26-qau-dilithium3-v1-dkg-session-derivation.md` for how a production
node derives that session from chain state.

The public matrix seed is derived separately from the same agreed randomness:

```text
rho = SHAKE256(
    "QAU-TDILITHIUM3-V1-MATRIX-SEED" ||
    session || committeeDigest || R
)[0:32]
```

This makes `rho` identical at all six participants without allowing the
coordinator to choose it after seeing any group seed. The complete ordered
randomness transcript and `rho` are included in the final DKG transcript digest.

### Round 2: Group Seed Distribution

For each of the 20 group masks, the current group leader samples a fresh
32-byte group seed and sends it separately to the other two group members over
the existing authenticated encrypted pairwise channel.

The seed message is bound to the session, committee digest, group mask, leader
position, recipient position, and attempt number. Recipients durably record the
message digest before acknowledging it. Seeds are never sent to the coordinator
unless the coordinator is itself a member of that group.

### Round 3: Component Derivation

All three group members derive identical component polynomials:

```text
(s1_U, s2_U) = ExpandMask3(
    "QAU-TDILITHIUM3-V1-RSS-COMPONENT" ||
    session || committeeDigest || groupMask || leaderPosition || R || groupSeed
)
```

`ExpandMask3` is a QAU domain-separated mode3 sampler. It produces the same
coefficient distribution used by the selected threshold-signing proof and must
not be implemented by calling ordinary mode3 private-key generation.

The initial implementation pins the paper's four-of-six parameter profile and
must reproduce deterministic vectors before activation. Any change to the
component distribution or signing rejection parameters creates a new threshold
protocol version.

The component coefficient bound is `+/-1`, not mode3's `Eta = 4`. Because the
signing secret is the sum of 20 components, a per-component bound of `4` gives an
aggregate bound of `80` and an effective signing bound `Beta_eff = 3920`, which
was measured to require roughly fifteen thousand rejected signing attempts per
signature. A per-component bound of `1` gives `Beta_eff = 980` and about eleven.
`2026-09-24-qau-dilithium3-v1-signing-mpc.md` carries the derivation and the
remaining lattice re-estimation obligation. mode3's `Eta` keeps its
compatibility value and is not reused as the component bound.

### Round 4: Partial Public Contributions

Each group member independently computes:

```text
t_U = A(rho) * s1_U + s2_U mod q
```

The members first broadcast a digest of the canonical `t_U` encoding. The group
passes only if all non-faulty members report the same digest. The current leader
then publishes `t_U`; the other members verify its bytes against both their
locally computed value and the agreed digest.

Publishing `t_U` is intentional. It is an LWE-style partial public contribution,
not a secret polynomial. The complete component `s1_U,s2_U` remains limited to
the three group members.

A group containing at most two corrupt participants always contains at least
one honest member. A malicious leader therefore cannot activate a false partial
public contribution without either an honest rejection or an attributable
conflict.

### Round 5: Public-Key Assembly

After all 20 group contributions are accepted, every participant computes:

```text
t = sum(t_U) mod q
(t1, t0) = Power2Round(t)
publicKey = rho || EncodeT1(t1)
```

Only `t1` enters the 1952-byte mode3 public key. `t0` is transient and is
immediately zeroized. It is not stored as a long-term share.

The threshold signing protocol derives the hint correction from the public
verification equation, following the referenced threshold construction,
instead of reconstructing or sharing `t0`.

All six participants must agree on the public key, the ordered set of 20
contribution digests, and the final transcript digest before producing an
activation acknowledgement.

## Complaints and Leader Replacement

Complaint reasons are restricted to:

- missing group seed;
- invalid authenticated seed envelope;
- conflicting seeds for one group attempt;
- invalid component encoding or coefficient range;
- partial-public-key digest disagreement;
- published partial public key differing from local computation;
- stale session, committee, group leader, or attempt number.

Evidence is one of: the dealer's signed seed envelope, a signed envelope that
contradicts another for the same group attempt, or a malicious dealer's disputed
seed. A complaint against an honest dealer cannot reveal an honest group seed
because the complainant cannot forge the dealer's authenticated message. A bare
message digest is not evidence — the complainant could have hashed an envelope it
built itself — and a missing seed leaves no envelope to disclose at all. When an
admissible complaint reveals a seed, the entire DKG attempt is aborted and all
derived components from that attempt are zeroized; the revealed seed is never
reused.

Leader replacement is allowed only before a group contribution becomes part of
the final transcript. Replacement increments the group attempt, selects the
next member, and requires a fresh seed. If all three leaders fail, the DKG
session aborts.

Attributability is a prerequisite for replacement, not a nicety. A complaint is
admissible only once the wire format carries the dealer's signed envelope and the
receiver verifies that signature against the committee roster; structural
validation alone is insufficient. Unattributable complaints, including a bare
claim that no seed arrived, are refused and never advance a group attempt, so a
leader that genuinely stalls fails the session closed instead of letting one
member burn attempts in the 20 canonical groups. Leader replacement therefore
stays unimplemented in this phase; the driver reports
`errTDilithium3DKGGroupStalled` and leaves the journal untouched.

## Crash Safety

Durable state transitions are monotonic:

1. session prepared;
2. public randomness contribution persisted;
3. group seed received and persisted;
4. component derived;
5. partial contribution verified;
6. all 20 contributions complete;
7. local share encrypted and installed;
8. activation acknowledgement persisted;
9. exact-epoch activation committed.

Secret group seeds and components are encrypted at rest. Journals store protocol
identity, committee digest, group mask, attempt, message digests, and completion
bits. A restart may resume an exact persisted attempt but cannot regenerate a
consumed seed or reinterpret state under another committee.

Partial installation never updates `active.enc` or the rollback ledger. The
active pointer advances only after all ten local components and the complete
20-contribution transcript validate.

## Signing Consequences

The signing backend must use the same replicated-component topology. For every
canonical four-member signer set, each of the 20 components is assigned to one
active holder using a deterministic allocation table or algorithm covered by
exhaustive tests. The allocation assigns exactly five components to each
signer: groups with one active holder are forced, the two groups for each
active pair are split between its holders, and the four three-active groups
are assigned one per active holder. This avoids a position-dependent signing
load while preserving unique ownership of every component.

No signer forms the sum of all components. Each signer computes responses only
for its assigned components, and the coordinator receives only commitment and
response aggregates defined by the threshold signing protocol.

The paper's four-of-six parameter profile uses many parallel rejection
candidates. QAU must independently pin and review the legacy mode3 values rather
than copying ML-DSA-65 constants without derivation. The 32-byte legacy
challenge and transcript hashes remain mode3-specific.

## Reshare and Committee Rotation

An RSS reshare transfers each old component into new committee components while
preserving the aggregate secret and public key. It must not reconstruct the
aggregate `s1` or `s2` at any participant.

The reshare design is a separate cryptographic gate. Until that design is
approved, a new committee may enter through a fresh DKG generation but cannot
claim same-key reshare support. Existing epoch scheduling and activation
machinery remains reusable after it is generalized to RSS component records.

## Failure Handling

- Any malformed fixed-size encoding fails before secret publication.
- Any duplicate or conflicting group record aborts the session.
- Any missing group prevents public-key assembly.
- Any public-key disagreement prevents all activation certificates.
- Any persistence metadata mismatch zeroizes decoded component material.
- Any ledger rollback or active-pointer mismatch remains fail-closed.
- No RSS failure may select the legacy QTD or ML-DSA experimental backend.

## Test Strategy

### Topology

- Enumerate exactly 20 unique three-member masks.
- Prove every participant owns exactly ten masks.
- Prove every four-member active set intersects every mask.
- Prove every coalition of at most three members misses at least one mask.
- Verify canonical position-to-validator mapping and encoding order.

### DKG

- Six independent processes derive one identical `rho` and public key.
- Every group has three matching component derivations.
- Changed session, committee, mask, leader, recipient, randomness, or seed
  changes the derived component or is rejected.
- Equivocation, missing delivery, invalid range, and false complaint are covered.
  Leader replacement is not: unattributable complaints are refused, and a stalled
  leader fails closed with `errTDilithium3DKGGroupStalled`, leaving the journal
  untouched.
- Fewer than 20 accepted public contributions cannot activate.
- Memory and serialized-state scans find no complete aggregate secret.

### Storage

- Exactly ten components round-trip through encrypted persistence.
- Duplicate, missing, foreign, and reordered masks are rejected.
- Failed decoding clears all already-decoded components.
- Restart resumes exact group attempts without seed reuse.
- Corruption, wrong password, conflicting overwrite, and rollback fail closed.

### Interoperability

- Aggregated public keys parse as ordinary 1952-byte mode3 keys.
- Final signatures are exactly 3293 bytes and pass unmodified `mode3.Verify`.
- Existing historical blocks remain verifiable without migration.

## Implementation Order

1. Replace single-share storage with fixed CNF component storage.
2. Implement and exhaustively test group topology and signer allocation.
3. Implement domain-separated component sampling and deterministic vectors.
4. Implement matrix expansion and partial public contribution computation.
5. Implement DKG randomness, private seed distribution, digest agreement, and
   complaints.
6. Assemble ordinary mode3 public keys without persisting `t0`.
7. Integrate crash journals and six-node DKG activation.
8. Adapt and validate the threshold signing construction.
9. Define RSS reshare before enabling same-key committee rotation.

Independent cryptographic review is not a step in this order. It is an external
third-party engagement that happens after the implementation is complete, and it
is not part of this project's development backlog.

## Acceptance Boundary

This architecture does not by itself establish production security. The DKG
becomes implementation-complete only when six separate node processes complete
all 20 groups, store only their ten components, agree on one standard mode3
public key, survive the defined crash tests, and expose no complete private key.

The six-runner cluster test uses an in-process memory transport, and the
authenticated six-node randomness test also runs six `Node` objects inside one
process. A separate cross-process test closes the gap those two leave: six
independent OS processes, each with a real `p2p.Host` over TCP and the encrypted
transport, complete the randomness round, all twenty canonical groups,
finalization, encrypted share persistence, and signed activation, then commit
one identical exact-epoch activation certificate and reload the active share the
way a restart would.

The session digest commits a canonical validator-address and identity-key roster
in addition to the numeric committee IDs, and the validator-snapshot adapter
checks that commitment before accepting a peer. The adapter still cannot
establish where the roster came from: it validates the snapshot it is handed and
cannot distinguish a finalized-epoch roster from the node's mutable current
validator set. The finalized-epoch source that supplies it is specified below in
"Finalized-Epoch Validator Snapshot" and implemented as option 2.

The full protocol remains experimental until the legacy mode3 signing parameter
derivation, RSS reshare, and adversarial tests are complete.

## Finalized-Epoch Validator Snapshot

Round 0 binds every participant to one session, and the session commits one
roster: the ordered validator addresses and Dilithium3 identity keys of the
committee. That commitment is only as trustworthy as its input. Nothing in the
current tree proves that the roster, or the keys inside it, were the ones active
at the session epoch on the finalized chain:

- `ValidatorSet` is mutable in-memory state. Its membership changes as blocks are
  processed (validator-manager admission and the staking-transaction sync path),
  and those changes carry no block or epoch tag, so the set as of a past epoch
  cannot be reconstructed.
- `EpochSummary` reports counts, not addresses or keys.
- `epochBlockRoots` maps an epoch to a block hash, not to a validator-set root.
- The state database has no validator concept at all.
- `GetCommitteeForSlot` returns the live set whenever the set is not larger than
  an epoch, which is the mainnet case.

A node that synced from a snapshot therefore cannot reproduce a past epoch's
roster, and a live node that substituted its current set would agree with peers
only by accident.

Requirement: for session epoch `E`, every participating node obtains the same
ordered `(validator address, identity public key)` list, can obtain it again
after a restart, and can establish that the list belongs to the finalized chain
at `E` rather than to local mutable state. When any part of that is unavailable
the DKG fails closed; it never degrades to the live set.

### Options

1. **Committed registry root (target).** Epoch `E`'s finalized data commits a
   canonical roster root, and a participant requires the session roster digest to
   equal that root. This is the only option that gives a node syncing from a
   snapshot an independent, chain-derived source of truth. It changes
   consensus-committed data, so it needs a fork and migration decision, and it
   requires membership changes to become epoch-indexed instead of taking effect
   at staking-transaction granularity.
2. **Locally persisted epoch index (no fork).** The node captures the canonical
   roster at each epoch boundary while processing blocks, persists
   `epoch → (roster, digest, boundary block hash)` in a bounded sidecar, and
   serves it again after a restart. Membership changes happen during block
   processing, so the captured value is identical on every node that processed
   the same blocks, and divergence fails closed at Round 0 instead of silently
   proceeding. This needs no consensus change. It depends on the invariant that
   *every* membership mutation is block-derived: any time-driven, governance-RPC,
   or local-policy mutation breaks determinism without any visible error, so that
   invariant has to be audited and enforced. A node that bootstrap-synced at or
   after epoch `E` cannot serve `E`; sessions must target epochs strictly after
   the bootstrap boundary and fail closed otherwise.
3. **Defer.** Keep both gates closed and make the missing source explicit:
   production wiring that builds a `DKGSession` must obtain the roster from a
   finalized-epoch source and must refuse to build a session otherwise.

Sequencing: 3 was the interim state, 2 is implemented below as the no-fork
solution, 1 remains the target if arbitration is required.

### Option 2 Implementation

Option 2 is implemented in the node layer (`node/tdilithium3_dkg_epoch_roster.go`
and the consumer helpers in `node/tdilithium3_dkg_validator_snapshot.go`):

- **Capture.** The hook runs on every path that applies a block's side effects —
  local production, sync import, and live P2P import. It records one roster per
  epoch. The boundary block (slot a non-zero multiple of `SlotsPerEpoch`, header
  epoch equal to `slot/SlotsPerEpoch`) captures with its own block hash as the
  anchor. When the boundary slot was missed, the epoch's FIRST canonical block
  captures instead and the anchor is that block's parent hash — the chain tip at
  the epoch boundary, byte-compatible with the R101 epoch-boundary-root rule
  (devnet evidence: without this rule a missed boundary slot permanently
  bricked every session anchored on the uncaptured epoch; see the R77 spec,
  section 6). An epoch whose slots were ALL missed has no canonical block to
  anchor on, stays uncaptured, and sessions referencing it fail closed
  identically on every node.
- **Content.** The captured roster is the active validator set projected to
  `(address, Dilithium3 identity key)` pairs, then sorted by address so insertion
  order cannot change the digest. An inactive validator, an empty or duplicate
  address, or a missing, truncated, degenerate, or unparsable identity key
  rejects the whole capture instead of producing a partial roster.
- **Chain binding.** The digest commits the chain id, the genesis block hash, the
  epoch, the boundary block hash, and every entry. A sidecar whose chain id,
  genesis hash, or internal digest does not match is refused, never repaired.
- **Bounds.** The sidecar keeps at most 64 epochs and 4096 entries in total,
  dropping the oldest epoch first, and is written atomically (temp file, `0600`,
  rename).
- **Bootstrap boundary.** The first captured epoch is recorded as the bootstrap
  boundary. Epochs at or below it are not servable, because a node that
  bootstrap-synced may only have observed a partially processed epoch.
- **Reorg and finality.** An epoch the node has not finalized may be replaced by
  the new canonical boundary after a reorg; re-delivering the same boundary is
  idempotent; a finalized epoch may not change.
- **Fail-closed.** Every missing, unfinalized, out-of-window, size-mismatched, or
  digest-mismatched request returns the named
  `errTDilithium3DKGEpochRosterUnavailable`. There is no fallback to the live
  set. The consumer maps committee position `i` to roster entry `i` and refuses a
  roster whose size differs from the committee rather than subsetting it, because
  committee selection is consensus state this layer does not reproduce.
- **Block-derived invariant.** The determinism claim only holds while every
  validator-set mutation is block-driven. `syncStakingFromBlock` and the
  slashing path are block-driven; the one RPC-facing mutation entry point
  (`consensusStakeUpdaterAdapter.UpdateValidatorStake`) had no production caller
  and now fails closed with
  `errConsensusStakeMutationNotBlockDerived` instead of mutating the set off the
  block path.
- **Gating.** The sidecar is created only while
  `QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1` is set, so a production node never
  touches the file and `finalizedEpochValidatorRoster` fails closed on every
  call.

### What the Committed Root Buys

Both options make the roster deterministic and make disagreement fail closed.
They differ in evidence, not in safety:

- Option 2 gives no arbitration. A node cannot show a peer, a light client, or an
  auditor which roster is correct without replaying, and producing a wrong roster
  has no attributable consequence.
- Option 1 makes the roster verifiable from finalized chain data alone, so a
  divergence is attributable and a light client can check it.

Option 2 is therefore sufficient whenever "no wrong roster is ever accepted" is
the acceptance criterion, and insufficient when accountability for a wrong roster
is required.

### Failure Semantics

A missing, unfinalized, or mismatched snapshot fails closed with a named error
before any session is constructed. No fallback to the live `ValidatorSet`. No
retry against a later epoch once peers have been bound. The roster check in
`newTDilithium3DKGInboxFromIdentitySnapshot` remains as an independent second
check on the same value.

### Out of Scope

Whether to fork, the encoding and location of the registry root, activation
queue semantics, and any change to staking activation timing. Each of these needs
its own change proposal.

### Verification

For option 1: a full-replay node and a snapshot-sync node derive identical roster
digests for the same finalized epoch; a node whose local set diverges from the
committed root refuses to construct a session; a restart between session
construction and Round 1 reproduces the same roster.

For option 2 (covered by `node/tdilithium3_dkg_epoch_roster_test.go`): two
validator insertion orders digest identical entries; the digest changes when the
chain id, genesis hash, epoch, boundary hash, roster length, address, or identity
key changes; a restarted node reproduces the captured epoch, boundary hash,
digest, and entries from the sidecar; the sidecar is bounded by the epoch budget;
an unfinalized epoch accepts the reorged boundary while a finalized one is
immutable; the bootstrap boundary and every missing, unfinalized, foreign-chain,
foreign-genesis, version-mismatched, digest-tampered, or malformed sidecar fails
closed on the named error; a session that commits a different roster, or a chain,
or an activation epoch without a snapshot never reaches the inbox; the capture
hook ignores non-boundary blocks and refuses a boundary block whose header epoch
disagrees with its slot; and the hook is a no-op while the experimental gate is
closed.

## References

- Carsten Baum, James Clements, Tjerand Silde, and Marc Stevens,
  "Efficient Threshold ML-DSA for Groups of up to 6 Signers," NIST PQC
  Conference 2025 and USENIX Security 2026.
- CRYSTALS-Dilithium specification, round 3, Dilithium3 parameter set.
- Cloudflare CIRCL v1.6.3 legacy `sign/dilithium/mode3` implementation.

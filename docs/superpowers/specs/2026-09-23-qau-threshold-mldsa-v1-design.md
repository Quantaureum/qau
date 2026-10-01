# QAU Threshold ML-DSA Protocol v1 Design

**Status:** Proposed experimental protocol

**Date:** 2026-09-23

## Purpose

QAU Threshold ML-DSA Protocol v1 replaces the current distributed signing
path that exposes secret-related `S2` and `T0` material to the aggregator.
The replacement must produce a standards-compatible ML-DSA-65 signature
without any participant, proposer, or aggregator reconstructing the group
private key.

This is a research-grade protocol and integration boundary. It is not a
production-security claim before independent cryptanalysis and external review.

## Current Boundary

The existing DKG, epoch transition, committee reshare, late-recipient recovery,
encrypted reshare journal, and historical group-key lookup are usable
engineering foundations. The existing distributed signing protocol is not a
safe foundation because its aggregator receives enough secret-related material
to recover the group signing key.

The replacement keeps the lifecycle integration but replaces the signing
backend and all secret-bearing signing messages.

## Compatibility Correction

The repository currently uses pre-standard Dilithium3:

- Public key size: 1952 bytes.
- Signature size: 3293 bytes.
- Verifier: CIRCL `sign/dilithium/mode3`.

FIPS 204 ML-DSA-65 is a different profile:

- Public key size: 1952 bytes.
- Signature size: 3309 bytes.
- Verifier: CIRCL `sign/mldsa/mldsa65` or an equivalent FIPS 204 verifier.

The two formats must not be inferred from length alone. Every group key and
finality seal carries an explicit algorithm identifier and key generation.
Historical Dilithium3 blocks remain verifiable; new v1 generations use
ML-DSA-65.

## Goals

Version 1 provides:

1. Standard ML-DSA-65 public keys and final signatures.
2. Dealerless distributed key generation.
3. Threshold signing that never sends private shares to the coordinator.
4. Dynamic reshare without reconstructing the private key.
5. Crash-safe single-use signing state.
6. Algorithm, key-generation, epoch, committee, and session binding.
7. Historical verification across key and algorithm rotations.
8. Fail-closed handling of malformed, replayed, conflicting, and stale data.
9. A replaceable cryptographic backend behind stable lifecycle interfaces.

## Non-Goals

Version 1 does not:

- Claim security solely because tests pass.
- Enable production signing without explicit operational acceptance.
- Support arbitrary committee sizes. The first instantiation accepts two to
  six participants and rejects larger configurations.
- Preserve the 3293-byte Dilithium3 format for new v1 generations.
- Reuse current signing messages or their `ScShare`, `S2Share`, or `T0Share`
  fields.
- Treat encryption to the aggregator as protection from the aggregator.
- Recover or reuse uncertain signing randomness after a crash.

## Cryptographic Profile

The first implementation is named `qau-tmldsa65-v1`.

It is a clean implementation of the public algebraic research approach for
efficient threshold ML-DSA in small committees. Standard primitive libraries
may provide SHAKE, polynomial arithmetic, and FIPS 204 encoding, but the node
does not depend on the inspected third-party threshold prototype at runtime.

Fixed profile properties:

- Signature algorithm: FIPS 204 ML-DSA-65.
- Active committee size: exactly `n = 6`.
- Authorization and reconstruction threshold: exactly `t = 4`.
- Corruption bound: a malicious coordinator and at most two colluding active
  participants must not recover the group private key or an honest
  participant's long-term share.
- Signing liveness requires four responsive honest participants. Malicious
  participants may force their own attempt to abort but cannot make an
  invalid signature verify.
- Nodes joining after the active committee is installed are observers for the
  current epoch. They become signing participants only through a later
  authenticated reshare and epoch activation.
- Malicious participants may abort; aborts must not leak the key or produce an
  accepted invalid signature.
- The output passes an ordinary ML-DSA-65 verifier without a threshold-specific
  verification path.

The profile remains experimental until the algebra, parameters, transcript,
and implementation are independently reviewed against the published
construction.

## Algorithm and Key Identity

```go
type SignatureAlgorithm uint16

const (
	SignatureAlgorithmDilithium3Legacy SignatureAlgorithm = 1
	SignatureAlgorithmMLDSA65          SignatureAlgorithm = 2
)

type ThresholdKeyID struct {
	Algorithm  SignatureAlgorithm
	Generation uint64
	PublicKey  []byte
}
```

`Generation` increases when DKG creates a new key. A reshare preserving the
public key preserves the generation and advances a separate committee version.
No verifier selects an algorithm only from key or signature length.

## Backend Boundary

```go
type ThresholdBackend interface {
	Algorithm() SignatureAlgorithm
	PublicKey() ThresholdKeyID
	StartSigning(SignRequest) (SigningAction, error)
	HandleSigningMessage(SigningMessage) (SigningAction, error)
	StartDKG(DKGRequest) (DKGAction, error)
	HandleDKGMessage(DKGMessage) (DKGAction, error)
	StartReshare(ReshareRequest) (ReshareAction, error)
	HandleReshareMessage(ReshareMessage) (ReshareAction, error)
	Verify(ThresholdKeyID, []byte, []byte, []byte) error
}
```

The backend returns messages, required durable transitions, and optional final
results. It performs no network I/O. P2P authentication, persistence, and
consensus activation remain outside the cryptographic core.

## Canonical Session Binding

Every signing attempt hashes this canonical transcript:

```text
QAU-TMLDSA65-V1-SIGN ||
chain_id || key_generation || committee_version || epoch || slot ||
domain || context || message_digest || sorted_participant_ids || attempt_nonce
```

The session identifier is `SHA3-256` of fixed-width big-endian integers and
length-prefixed variable fields. Participant identifiers are sorted and unique.
Every message carries the complete binding metadata and an identity signature.
A mismatch is rejected before the cryptographic backend receives the message.

## Signing State Machine

```text
Created -> Prepared -> Committed -> Responded -> Finalized
                         |             |
                         +-> Burned <---+
```

- `Created`: request validated; no ephemeral secret exists.
- `Prepared`: ephemeral state is encrypted and durable.
- `Committed`: a public commitment was released.
- `Responded`: the exact response was durably marked consumed before release.
- `Finalized`: the ordinary ML-DSA-65 verifier accepted the final signature.
- `Burned`: the state can never be used again.

Transitions are monotonic. No committed, responded, finalized, or burned state
returns to prepared.

## Crash-Safe Single-Use Rule

Participants perform this order:

1. Generate ephemeral signing material.
2. Encrypt and persist the prepared record.
3. Sync the record.
4. Release the public commitment.
5. Compute the response after the canonical challenge is fixed.
6. Atomically persist `Responded` and a digest of the exact response.
7. Sync the consumed marker.
8. Release the response.
9. Zeroize in-memory ephemeral material.

Restart rules:

- `Prepared` may resume only when no commitment was released.
- `Committed` without a durable response is burned.
- `Responded`, `Finalized`, and `Burned` never produce another response.
- An uncertain send result is treated as sent and consumed.

Process-crash recovery uses an encrypted append-only hash-chained ledger with a
monotonic sequence number. The ledger detects partial state rollback and
corruption when its committed head remains available. A full-machine snapshot
that rolls back both state and the ledger cannot be detected by local storage
alone. Production eligibility therefore requires an external monotonic anchor,
such as a TPM/HSM counter or a separately administered append-only service.

## Coordinator Safety

The coordinator receives only public commitments, public transcript values,
construction-defined authenticated responses, complaints, blame evidence, and
the final signature. Wire types cannot contain serialized long-term shares,
weighted shares, complete key components, or equivalents of `ScShare`,
`S2Share`, and `T0Share`.

Changing coordinator creates a new session and burns committed state from the
abandoned session.

## Dealerless DKG

The authenticated DKG performs:

1. Contribution commitment and proof publication.
2. Encrypted recipient-specific share distribution.
3. Recipient verification against public commitments.
4. Signed complaints for invalid or missing shares.
5. Deterministic derivation of the qualified set.
6. Installation of only the local final share.
7. Agreement on one ML-DSA-65 public key and generation identifier.

No process serializes or persists the complete private key. Central key
generation is allowed only in isolated interoperability tests and is not
reachable from node code.

Activation requires agreement on transcript digest, qualified set, algorithm,
generation, the fixed `4-of-6` profile, participant set, and public key. A DKG
that qualifies fewer than six participants does not activate a reduced
committee; it aborts and must be restarted with a separately selected six-node
committee.

## Dynamic Reshare

Reshare preserves algorithm, generation, and public key while advancing the
committee version.

- The old threshold authorizes the reshare transcript.
- The old and new active committees each contain exactly six participants and
  use threshold four.
- Recipient contributions are authenticated and encrypted.
- New shares are verified before installation.
- Old shares retire only after new shares and activation data are durable.
- Old and new committee shares cannot mix in one signing session.
- Failed or incomplete reshare cannot activate the new committee.
- Late recipients resume the exact journaled transcript and contributions.
- A newly connected node cannot receive an ad-hoc signing share for the active
  epoch. It must be selected into a future six-node committee and receive its
  share through the corresponding reshare transcript.

### Batched linear consistency checks

The experimental reshare implementation uses degree-three Shamir polynomials
over the ML-DSA coefficient field. A dealer plan weights the old local share by
its four-dealer Lagrange coefficient and evaluates one stable polynomial for
all six new recipients. Production code never reconstructs the polynomial
constant or the shared `s1`, `s2`, or `t0` vectors.

Recipient contributions are checked without opening their 4,352 secret field
coefficients:

1. The dealer publishes the ordered six-recipient commitment set.
2. All six recipients commit to independent 32-byte nonce shares.
3. After every nonce commitment is fixed, all recipients reveal their shares.
   The XOR is the post-commitment challenge nonce. A missing or invalid reveal
   aborts the reshare.
4. The transcript derives eight independent random linear projections of every
   recipient contribution.
5. Two Reed-Solomon parity checks test that the six projected values are
   evaluations of one degree-three polynomial.
6. A separate interpolation check binds the projected polynomial constant to
   the dealer's Lagrange-weighted old local share.
7. Every sender masks each public check term with fresh pairwise zero-sum masks
   derived from direct authenticated post-quantum participant channels.
8. Senders commit to the masked term with a fresh 32-byte blinding salt before
   any term is revealed. The coordinator verifies every reveal and learns only
   the final syndrome.
9. Every syndrome must be zero. A non-zero syndrome, equivocation, missing
   commitment, missing reveal, or metadata mismatch aborts activation and burns
   the session state.

The random projection gives a probabilistic degree and constant-link test. Its
soundness assumes the dealer cannot predict or bias the joint nonce after the
contribution commitments are fixed, pairwise masks are fresh for every
round/check, and at least one honest nonce share remains unpredictable at
commit time. These assumptions and the eight-round parameter remain documented
caveats for external review.

The implementation now includes a deterministic coordinator state machine for
contribution-view agreement, nonce commitment and reveal, all twenty-four
masked-term checks, equivocation detection, timeout aborts, hash-chained event
replay, encrypted node-local transcript persistence, contribution-to-transcript
binding, and durable local share activation at an exact epoch. The activation
pointer is written only after the verified candidate share is durable; prior
candidate files remain available for historical recovery but are not selected
for signing.

The implementation now multiplexes canonical v1 control messages over the
existing authenticated TSS reshare route, validates sender-to-participant
binding, applies events to a cloned transcript, and persists the new state
before accepting it. The existing authenticated Kyber768 validator session now
provides a domain-separated exporter that feeds the pairwise mask derivation
without exposing AEAD keys; opposite participants derive cancelling masks.

The implementation now includes the participant runner, private point-to-point
contribution delivery, retry and timeout scheduling, signed abort evidence,
six-party activation acknowledgements, certificate assembly, certificate
rebroadcast, exact-epoch activation, and fail-closed routing from the consensus
reshare adapter. A six-node in-memory acceptance test drives four dealers
through every one of the eight rounds and three checks, restarts participants
after nonce and term persistence, assembles the activation certificate, and
restores all six activated shares. Live multi-process acceptance remains
required before a release claim.

## Persistence

```text
<key-state>.tmldsa-v1/
  key-metadata.enc
  generations/<generation>.enc
  sessions/<session-id>.enc
  ledger/head
  ledger/segments/<sequence>.enc
```

Records include format version, algorithm, key generation, committee version,
participant, session where applicable, sequence number, previous-record hash,
and payload digest. Metadata mismatch, duplicate sequence, broken chain, or
rollback behind an available committed head disables signing. Local-only
storage does not claim protection against rollback of the complete machine.

## Wire Protocol

```go
type ThresholdEnvelope struct {
	ProtocolVersion   uint16
	Algorithm         SignatureAlgorithm
	MessageType       uint16
	KeyGeneration     uint64
	CommitteeVersion  uint64
	SessionID         [32]byte
	SenderID          uint32
	Sequence          uint32
	Payload           []byte
	IdentitySignature []byte
}
```

Decoding is bounded before allocation. Unknown versions, algorithms, message
types, and non-canonical encodings are rejected. Legacy signing messages are
never accepted as v1 messages.

## Consensus Integration

Finality metadata records algorithm, key generation, committee version, key
reference, and final signature. Historical verification resolves the key by
algorithm and generation:

- Legacy generations use Dilithium3 mode3 verification.
- Version 1 generations use FIPS 204 ML-DSA-65 verification.

Activation order is: DKG or reshare completion, durable local share, signer
rebind, committed activation certificate, then signing eligibility.

## Failure Semantics

- Insufficient participants: no signature.
- Invalid contribution: reject and retain blame evidence.
- Conflicting message: burn the session.
- Timeout after commitment: burn the session.
- Persistence failure: send no protocol output.
- Final verification failure: reject and burn the session.
- Unknown generation: reject the block or seal.
- Unsupported committee size: reject before DKG.

Fallback to legacy distributed signing is forbidden for a v1 generation.

## Feature Gates

```text
QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1=1
```

The switch is required to create or use a v1 generation. Existing legacy gates
do not enable v1, and v1 never silently falls back to the legacy protocol.

## Required Tests

### Interoperability

- Public keys parse as ML-DSA-65 keys.
- Final signatures are exactly 3309 bytes.
- An independent ordinary ML-DSA-65 verifier accepts them.
- Changed messages, contexts, keys, and signatures fail.

### Secret-flow invariants

- Wire payloads contain no serialized long-term share.
- Coordinator-visible data never enters a private-key reconstruction API.
- No coordinator code path imports or constructs a complete private key.

These are implementation invariants, not a cryptographic proof.

### Single-use state

- Restoring a pre-response snapshot cannot create a second response.
- Crash before commitment may resume.
- Crash after commitment burns the session.
- A durable consumed marker prevents another challenge response.
- Concurrent duplicates produce at most one response.
- Partial rollback with an intact ledger head fails closed.
- Full-machine rollback protection is tested only when an external monotonic
  anchor is configured.

### DKG and reshare

- Independent processes derive one public key and retain local shares only.
- Invalid shares lead to one deterministic qualified set.
- Rotation preserves the key and changes holders.
- Late recipients recover from the journal.
- Old and new shares cannot mix.

### Local acceptance

- One run performs fresh v1 DKG, finality, reshare, delayed recovery, and finality
  under the rotated committee.
- Participant and coordinator crashes are injected independently.
- All nodes agree on the chain and historical signature validity.
- No legacy secret-bearing signing message is emitted.
- Race detection and a multi-hour soak pass.

## Review and Release Gates

1. `experimental`: implementation and local tests only.
2. `research-preview`: public specification, vectors, and reproducible tests.
3. `audit-candidate`: internal review complete with no critical finding.
4. `reviewed-experimental`: independent cryptographic review complete.
5. `production-eligible`: cryptographic review, code audit, interoperability,
   adversarial testing, and operational acceptance all pass.

The stage ladder records evidence maturity; enabling v1 is a separate
operational decision made with the single switch above.

Stages 4 and 5 depend on external third-party engagements (independent
cryptographic review, independent code audit). They are not development tasks in
this project's backlog: this project's own work stops at producing and
maintaining stage 3 (`audit-candidate`) evidence, and must not claim any stage
beyond the one that evidence actually supports.

## Implementation Layers

1. Algorithm identifiers and dual verification.
2. Protocol-neutral backend interfaces.
3. Canonical transcripts and authenticated envelopes.
4. Durable single-use ledger.
5. ML-DSA-65 arithmetic and encoding compatibility.
6. Experimental threshold signing core.
7. Dealerless DKG and complaint handling.
8. Dynamic reshare adapter.
9. Node P2P orchestration.
10. Consensus key-version integration.
11. Multi-process adversarial acceptance.

Each layer remains disabled by default until its tests pass. No layer removes
legacy safety gates or makes the experimental protocol a production default.

## Permitted Claim

Before any external independent review completes, the only permitted claim is:

> QAU contains an experimental threshold ML-DSA-65 implementation with
> dealerless lifecycle integration, durable single-use state, and standard
> ML-DSA-65 output. It has not completed independent cryptographic review and
> is not enabled by default.

The project must not claim that it is the world's first, fully secure, audited,
or production-ready without verifiable evidence.

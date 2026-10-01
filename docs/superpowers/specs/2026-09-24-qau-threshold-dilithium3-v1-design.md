# QAU Threshold Dilithium3 Protocol v1 Design

**Status:** Approved architecture; cryptographic construction and implementation remain experimental

**Date:** 2026-09-24

## Purpose

QAU Threshold Dilithium3 Protocol v1 defines a dealerless, rotating, crash-safe
threshold-finality protocol for the legacy CIRCL Dilithium mode3 signature
format already used by the chain.

The protocol keeps the existing chain signature profile:

- Public key: 1952 bytes.
- Private key encoding: 4000 bytes.
- Final signature: 3293 bytes.
- Verification: unmodified CIRCL `sign/dilithium/mode3.Verify`.
- Threshold profile: exactly four-of-six.

The complete group private key must never exist in a node, coordinator,
journal, message, production test helper, or recovery tool. This document does
not claim production security. Production eligibility requires deterministic
vectors and an implementation audit, and is an operational decision rather than
a code gate.

## Compatibility Decision

The experimental threshold ML-DSA-65 work remains isolated as research code.
It is not the production target for QAU finality. The production target remains
`SignatureAlgorithmDilithium3Legacy` and the 3293-byte mode3 signature format.
Existing blocks, transactions, validator keys, addresses, and historical
verification rules are not migrated to 3309-byte ML-DSA-65.

The existing experimental work is reused only where it is algorithm-neutral:

- canonical key and committee identities;
- authenticated bounded envelopes and transcript binding;
- crash-safe single-use state and encrypted journals;
- epoch scheduling, exact activation, and activation certificates;
- P2P routing, replay rejection, and evidence transport;
- six-node reshare and failure-injection infrastructure.

ML-DSA-specific encodings, parameters, rounding, hints, signature assembly, and
MPC equations are not reused without a Dilithium3 derivation and test vector.

## Fixed Security Profile

- Active committee: exactly six participants.
- Signing threshold: exactly four participants.
- Each attempt uses exactly four canonically ordered participants.
- Active corruption bound: at most two malicious participants.
- Coordinator: fully malicious and not trusted with secrets.
- Network: authenticated and asynchronous within configured deadlines.
- Four responsive honest participants can complete a fresh attempt.
- Malicious participants may abort but cannot forge or recover an honest share.
- Activation requires all six shares installed and acknowledged.
- Reduced committees such as four-of-five are forbidden.
- Late joiners enter only through a future reshare or new DKG generation.

Four shares authorize signing. Security against a malicious coordinator and two
corrupt participants additionally requires authenticated MPC for non-linear
rounding and signing operations.

## Goals

1. Dealerless generation with no complete private key.
2. One mode3-compatible public key agreed by all six participants.
3. One long-term local share per participant.
4. One ordinary 3293-byte mode3 signature from four participants.
5. No secret-share or reconstructable secret delivery to the coordinator.
6. Six-to-six reshare without key reconstruction.
7. Crash-safe single-use signing state.
8. Binding to chain, generation, committee, epoch, slot, domain, message,
   participant set, and attempt nonce.
9. Historical verification across key and committee rotations.
10. Evidence-bearing rejection of malformed, conflicting, replayed, and stale data.

## Non-Goals

- Changing ordinary validator or wallet signatures.
- Migrating historical data to ML-DSA-65.
- Supporting arbitrary committee sizes or thresholds.
- Treating transport encryption as protection from the coordinator.
- Using a trusted dealer in production.
- Exposing production share reconstruction helpers.
- Falling back to the aggregator-recoverable legacy signer.
- Activating a partial DKG or reshare.
- Claiming production readiness without verifiable evidence.

## Chosen Architecture

Modifying the ML-DSA package in place is rejected because its encodings and
rules differ. Extending the current QTD signer is rejected because its
aggregator receives secret-related `Sc`, `S2`, and `T0` material.

The selected approach is a new `dilithium3v1` cryptographic backend over the
generic lifecycle. Experimental ML-DSA code remains isolated and disabled.

Signature encoding and threshold protocol identity are separate:

- Signature algorithm: `SignatureAlgorithmDilithium3Legacy`.
- Threshold protocol: `ThresholdProtocolDilithium3V1`.
- Wire version: version 1.

Protocol identity is carried by DKG, reshare, signing, share state, journals,
activation certificates, and envelopes. It is never inferred from lengths.

The target package boundary is:

```text
wallet/tss/protocol/
    backend.go, envelope.go, profile.go, single_use.go, transcript.go, types.go
    dilithium3v1/
        params.go, poly.go, encoding.go, share.go
        dkg.go, dkg_power2round.go, complaints.go
        preprocess.go, mpc.go, sign.go, reshare.go
        activation_certificate.go, abort_evidence.go
    mldsa65/
        ... retained experimental code ...
```

The backend performs no network I/O and does not read consensus state. It
consumes validated requests and emits actions, durable-transition requirements,
evidence, or a final signature.

## Dilithium3 Compatibility Invariants

The implementation is pinned to the mode3 behavior used by the current chain.
Tests record the exact CIRCL version and verify at least:

- `N = 256` and `Q = 8380417`;
- mode3 dimensions and secret distributions;
- 1952-byte public-key encoding;
- 4000-byte private-key compatibility in isolated reference tests only;
- 3293-byte signature encoding;
- mode3 challenge, rounding, decomposition, hint, and rejection rules;
- no ML-DSA signing context in the legacy verification path.

Production code never generates or serializes the complete 4000-byte group
private key. A complete reference key is allowed only in isolated compatibility
tests that do not consume production shares.

## Long-Term Share State

Each participant stores only its local shares of the mode3 secret components,
including the equivalents of `s1`, `s2`, and `t0`, plus public metadata.

Every share record is bound to:

- threshold protocol and signature algorithm;
- key generation and committee version;
- participant identifier and ordered participant set;
- threshold and public key;
- DKG or reshare transcript digest;
- activation epoch and retirement state.

Persistence rejects any protocol, algorithm, generation, committee,
participant, public-key, or transcript mismatch before loading secret bytes.

## Dealerless DKG

### Preconditions

All six participants agree on the chain ID, activation epoch, protocol,
algorithm, generation, committee version, ordered validator identities,
threshold, session identifier, deadlines, and message-size limits. The ceremony
does not start if any value differs.

### Secret Contributions

Each participant independently samples valid small mode3 secret contributions.
No common seed generates the combined secret, and the coordinator does not
choose participant randomness.

Each participant publishes binding commitments and privately distributes
recipient-specific shares. Private contributions are authenticated, encrypted
to their recipient, transcript-bound, and persisted before transmission is
reported as complete.

### Commitment Boundary

The current Pedersen/Feldman infrastructure may be reused only after proving
that its scalar-field representation, coefficient mapping, range checks, and
binding properties correctly cover the Dilithium ring values. Otherwise v1
must use a ring-compatible commitment or separately reviewed proof system.

Hash-only commitments are insufficient. A receiver must verify its private
share against public commitments without learning another receiver's share.

### Distributed Public-Key Derivation

The combined public relation is derived from the sum of participant secret
contributions. The public `rho` and matrix derivation are canonical and
transcript-bound.

Distributed `Power2Round` is a hard cryptographic boundary. No participant or
coordinator may reconstruct the complete pre-rounded vector or complete `t0`.
The subprotocol must provide:

- exact mode3 coefficient semantics;
- authenticated shares or equivalent integrity protection;
- correct range and carry handling;
- no opening of secret low bits;
- deterministic public `t1` output;
- non-leaking complaint evidence;
- vectors comparing distributed results with reference mode3 `Power2Round`.

The DKG backend remains disabled until the exact distributed rounding
construction and its security argument are documented and reviewed.

### Complaints and Completion

Signed complaints cover missing, malformed, conflicting, or
commitment-inconsistent shares. Handling is deterministic and transcript-bound.

All six selected members must qualify and install a share. Fewer than six
qualified participants abort the ceremony. Consensus may select a replacement
committee and start a new generation, but it cannot activate a reduced group.

Completion requires agreement on protocol, algorithm, generation, committee,
qualified set, public key, transcript digest, durable local installation, and a
six-party activation certificate. Intermediate secret material is zeroized on
completion or abort.

## Threshold Signing

### Attempt Selection and Binding

Each signing attempt uses exactly four sorted participant identifiers selected
from the active six-member committee. A failed attempt never changes its
participant set. A retry uses a fresh nonce, session identifier, and single-use
preprocessing records and may select a different four-member subset.

Every attempt commits to:

```text
QAU-TDILITHIUM3-V1-SIGN ||
chain_id || protocol || algorithm || key_generation || committee_version ||
epoch || slot || domain || message_digest || sorted_participant_ids ||
attempt_nonce
```

Integers use fixed-width big-endian encoding and variable fields use explicit
length prefixes. Every message carries the resulting session identity.

### Required Secure Operations

The mode3 signing backend securely realizes:

1. distributed one-time randomness generation;
2. distributed computation of the public commitment relation;
3. high-bit extraction without opening the complete secret-dependent vector;
4. canonical mode3 challenge derivation;
5. authenticated multiplication of the challenge by shared secrets;
6. distributed response generation;
7. infinity-norm checks without opening rejected secret values;
8. mode3-compatible low-bit and hint computation;
9. canonical 3293-byte signature assembly;
10. unmodified mode3 verification before release.

The coordinator may not receive reconstructable values equivalent to `y`,
`s1`, `s2`, `t0`, complete `w`, low bits, or four long-term shares.

### Preprocessing and Single Use

Non-linear operations use one-time preprocessing generated without a trusted
coordinator. Each record has a public commitment, local opaque secret handle,
protocol and committee identity, unique identifier, and monotonic state.
Encrypting locally generated masks to the coordinator is not sufficient.

Each participant enforces:

```text
Created -> Prepared -> Committed -> Responded -> Finalized
                         |             |
                         +-> Burned <---+
```

- `Prepared`: ephemeral state is encrypted and durable.
- `Committed`: a public commitment has been released.
- `Responded`: the exact response is durably consumed before release.
- `Finalized`: the final mode3 signature has verified.
- `Burned`: the record can never produce another response.

After restart, a committed record without a durable response is burned.
Responded, finalized, and burned records never respond again. An uncertain send
is treated as sent. Coordinator replacement burns the abandoned attempt.

Mode3 rejection sampling burns the committed attempt and retries with entirely
fresh state. A coordinator cannot probe one record with multiple challenges.

## Dynamic Reshare

Reshare preserves the algorithm, group public key, and key generation while
advancing the committee version.

Exactly four canonically selected old participants authorize one attempt. Their
weighted old-share contributions are redistributed to exactly six new members
without reconstructing the group secret.

The reshare requires authenticated recipient-encrypted contributions, public
consistency commitments, deterministic dealer selection and Lagrange weighting,
verification of every new share, an unchanged public key, six durable installs,
and a six-party activation certificate.

Existing experimental reshare state machines, journals, nonce commitments,
masked consistency rounds, and activation certificates may be generalized.
Their field operations and share encodings require a Dilithium3-specific audit.

Old and new shares cannot mix in one signing session. A failed reshare leaves
the old committee active until consensus selects a recovery action. A delayed
recipient resumes the exact journaled bytes and does not receive regenerated
contributions. Old shares retire only after exact-epoch activation is durable.

## Epoch and Consensus Integration

Ordinary QPOS proposer and attester behavior remains unchanged. Threshold
Dilithium3 finality is an additional committee duty:

```text
active validator set
-> deterministic six-member selection
-> pre-activation DKG or reshare
-> six-party activation certificate
-> exact epoch activation
-> four-party threshold finality attempts
-> later reshare or new DKG generation
```

Activation verifies chain ID, epoch, election result, protocol, algorithm, key
generation, committee version, public key, transcript digest, and six validator
identity signatures. Members acknowledge only after durable local installation.

Stale asynchronous completion cannot activate another epoch or participant
set. A newer epoch cannot overwrite an unresolved transition, and epoch
rollback is rejected. Finality signing binds a canonical checkpoint or reviewed
block root, never arbitrary coordinator-provided bytes.

## Coordinator Rules

The coordinator is a replaceable orchestration role, not a key holder. It may
receive public commitments, approved public openings, transcript values,
bounded complaint evidence, safe final signature components, and the final
signature.

It may not receive long-term shares, weighted shares, complete private-key
components, reusable masks, or secret handles resolvable outside a participant.
Signature assembly verifies before publication. Verification failure burns the
attempt and never falls back to the unsafe legacy signer.

## P2P and Message Validation

Every DKG, reshare, preprocessing, and signing message uses the common bounded
envelope with explicit threshold-protocol identity. The validator identity
signature covers the complete canonical envelope except its signature field.

Receivers reject:

- unknown protocol or message versions;
- protocol and signature-algorithm mismatch;
- oversized payloads or malformed polynomial encodings;
- unknown senders or validator identity mismatch;
- duplicate, conflicting, or non-monotonic sequences;
- cross-session, cross-generation, cross-committee, or cross-epoch messages;
- messages outside the current state-machine round;
- expired rounds and stale retransmissions.

Per-peer and global limits bound sessions, buffered bytes, evidence, and
retransmissions.

## Persistence and Rollback Boundary

Shares, private contributions, preprocessing records, signing records, and
activation state are encrypted at rest and written atomically.

An append-only hash-chained local ledger detects process crashes, partial
writes, truncation, and rollback while its committed head remains available.
It cannot detect a full-machine snapshot restoring both state and ledger.
Production eligibility therefore requires an external monotonic anchor such as
a TPM/HSM counter or independently administered append-only service.

## Rewards and Penalties

Committee economics are separate from proposer and attester rewards.

- Validators outside the committee retain ordinary duties and rewards.
- Selected validators earn committee rewards only for authenticated,
  verifiable DKG, reshare, activation, or signing participation.
- Selected but absent validators receive no committee service reward.
- Transient timeout penalties are distinct from cryptographic slashing.
- Provable equivocation, conflicting shares, forged evidence, or intentional
  invalid messages may trigger slashing after consensus validation.
- Audit-only sealer accounting is not payment; acceptance requires observable
  balance deltas.

Economics follows cryptographic and consensus correctness and does not gate the
first local protocol tests.

## Feature Gates and Fallback Policy

Threshold Dilithium3 v1 is disabled by default until the operator enables it.
Activation is one switch (`QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1`) and
carries no separate acknowledgment gate.

An unavailable or failed v1 backend must not silently select:

- the aggregator-recoverable legacy signer;
- a trusted-dealer key;
- the ML-DSA-65 experimental backend;
- an ordinary single-validator signature presented as threshold finality.

Threshold finality fails closed. Ordinary QPOS behavior follows its separately
defined consensus fallback policy.

## Compatibility and Migration

Deployment adds threshold metadata without rewriting history:

- Historical 3293-byte signatures verify unchanged.
- Validator and wallet signatures remain unchanged.
- Existing addresses remain unchanged.
- ML-DSA experimental state is not imported into Dilithium3 v1.
- Existing unsafe threshold shares are not converted into v1 shares.
- The first v1 generation is created by a fresh six-node DKG.
- Consensus activates it only at an explicit future epoch.
- Historical group public keys remain available for verification.

## Test Strategy

### Unit and Interoperability

- Parameters and encoded sizes match the pinned CIRCL mode3 implementation.
- Polynomial, rounding, decomposition, norm, hint, and encoding operations
  match reference vectors.
- Distributed `Power2Round` matches reference results on non-production inputs.
- Final signatures are 3293 bytes and pass unmodified `mode3.Verify`.
- Malformed and non-canonical encodings are rejected.
- Protocol separation prevents ML-DSA and Dilithium cross-use.

### DKG

- Six independent processes complete one dealerless DKG.
- All honest participants agree on public key and transcript digest.
- No process serializes the complete private key.
- Missing, malformed, conflicting, replayed, and cross-session shares abort.
- Two malicious contributions cannot activate different honest public keys.
- Fewer than six installed shares cannot produce an activation certificate.

### Signing

- Every honest four-member subset can produce a valid signature.
- Three members cannot produce a valid signature.
- Two corrupt participants and a malicious coordinator cannot recover the key.
- Rejection retries use fresh one-time state.
- Crash injection covers each durable transition and send boundary.
- Coordinator replacement burns the abandoned attempt.
- Memory and message inspection finds no complete key or prohibited component.

### Reshare and Epoch

- Six-to-six reshare preserves public key and generation.
- Committee version advances exactly once.
- Old and new shares cannot mix.
- Delayed recipients resume exact persisted transcripts.
- Recipient crash after durable receipt recovers safely.
- Partial installation never activates.
- Exact epoch activation succeeds across six local node processes.
- Stale completion, epoch rollback, and overlapping rotation are rejected.

### Network and Operations

- Six baseline nodes plus separately started late joiners.
- Packet duplication, reordering, delay, loss, and bounded partition.
- Process termination and restart in every protocol round.
- Decoder fuzzing, race detector, resource limits, and long-running soak.
- Consecutive rotations followed by historical finality verification.
- Observable committee reward balance deltas after economics integration.

## Release Stages

1. `experimental`: unit tests and deterministic vectors.
2. `research-preview`: six-process DKG and signing behind feature gates.
3. `audit-candidate`: adversarial, crash, race, soak, and rollback tests complete.
4. `reviewed-experimental`: independent cryptographic findings resolved.
5. `production-eligible`: implementation audit, external rollback anchor, and
   operational acceptance complete.

No earlier stage may be described as audited, production-ready, or proven secure.

## Required Review Artifacts

Before `audit-candidate`, reviewers receive:

- complete equations, notation, adversary model, and network model;
- distributed `Power2Round` construction;
- preprocessing and authenticated multiplication construction;
- high-bit, norm, rejection, and hint MPC construction;
- transcript and message encodings;
- deterministic interoperability vectors;
- abort and complaint leakage analysis;
- coordinator-plus-two-corrupt-participants simulation argument;
- side-channel and memory-erasure review notes;
- a trace from final bytes to unmodified mode3 verification.

## Delivery Order

1. Generalize protocol identity and algorithm-neutral lifecycle code.
2. Add isolated Dilithium3 parameters, encodings, and reference vectors.
3. Implement DKG commitments, private distribution, and complaints.
4. Define and implement distributed `Power2Round`.
5. Implement durable share installation and six-party activation.
6. Define and implement authenticated preprocessing and signing MPC.
7. Produce valid 3293-byte signatures in isolated tests.
8. Generalize reshare, late-recipient recovery, and crash journals.
9. Connect P2P orchestration and exact epoch activation.
10. Run six-node DKG, signing, rotation, crash, adversarial, race, and soak tests.
11. Connect committee rewards and penalty evidence.

Independent cryptographic review is not a step in this order. It is an external
third-party engagement that happens after the implementation is complete, and it
is not part of this project's development backlog.

## Acceptance Definition

The objective is closed only when:

- six real node processes generate one group public key without a dealer;
- every participant stores only its own share;
- any honest four-member subset produces a 3293-byte signature accepted by
  unmodified mode3 verification;
- three or fewer shares cannot sign;
- the stated malicious coordinator and two-participant model is satisfied;
- DKG, signing, and reshare survive the defined crash tests;
- six-to-six rotation activates at the exact epoch;
- late joiners enter only through future authenticated reshare;
- historical finality remains verifiable;
- no unsafe fallback is reachable.


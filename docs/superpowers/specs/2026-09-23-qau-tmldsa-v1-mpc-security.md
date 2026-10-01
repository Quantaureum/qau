# QAU Threshold ML-DSA v1 MPC Security Boundary

## Status

This document defines the security contract for the experimental
`qau-tmldsa65-v1` online signing core. It is not a proof and does not make the
implementation production-eligible. The implementation remains disabled
unless the explicit operator switch is enabled.

## Fixed Profile

- Active participants: exactly six.
- Authorization threshold: exactly four.
- Active corruption bound: at most two participants.
- Coordinator: fully malicious and not counted as an honest participant.
- Output: one ordinary FIPS 204 ML-DSA-65 signature.
- Late joiners: excluded from the active epoch and admitted only by a future
  authenticated six-to-six reshare.

The threshold and corruption bound are separate. Four shares are required to
reconstruct a long-term secret value. Active security is required only against
two corrupt participants because six-party malicious-secure computation with a
four-share reconstruction threshold needs authenticated preprocessing or an
equivalent mechanism for non-linear operations.

## Long-Term Secrets

Each participant stores only its local shares of `s1`, `s2`, and `t0`. No node,
coordinator, journal record, message, or production helper may materialize:

- the complete ML-DSA private key;
- four local shares in one address space;
- an interpolation helper capable of reconstructing production shares;
- the standard private-key encoding;
- a reusable nonce seed shared with the coordinator.

The public key, `tr`, committee identity, generation, and transcript digests are
public values.

## Coordinator View

The coordinator may receive only:

- session, key, committee, participant, and sequence identifiers;
- commitments to one-time preprocessing records;
- public challenge material derived from approved openings;
- construction-defined proof or complaint digests;
- authenticated abort evidence;
- the final standard signature.

The coordinator view must not contain serialized polynomials for `s1`, `s2`,
`t0`, nonce shares, Beaver-style masks, authentication keys, or any opaque
secret handle that can be resolved outside the participant process.

Encryption to the coordinator is transport protection and is not accepted as
protection from the coordinator.

## One-Time Preprocessing

Every preprocessing record has a random identifier, a public commitment, a
private local handle, and a monotonic state:

```text
available -> committed -> burned
          \-> burned
```

The participant durably commits the record to one signing session before it
sends a construction-defined response. A crash after commitment burns the
record. Malformed openings, equivocation, transcript mismatch, cancellation,
or any attempted reuse also burn it. There is no transition from `burned`.

This state machine does not itself create secure preprocessing. The protocol
must later supply a reviewed dealerless method for authenticated multiplication
and non-linear operations. Until that construction exists and is reviewed, the
online signing backend cannot be called complete.

## Required Secure Operations

The MPC implementation must expose only opaque local handles and must realize:

1. high-bit extraction from a shared ring vector without opening the full
   vector;
2. infinity-norm comparison without opening rejected secret values;
3. canonical hint generation with only the standard sparse hint disclosed;
4. authenticated opening of explicitly public transcript values;
5. challenge derivation from `mu` and the canonical encoded high bits;
6. malicious-participant complaint evidence that does not reveal an honest
   long-term or ephemeral share.

Any implementation that reconstructs `w`, `y`, `s1`, `s2`, `t0`, `r0`, or an
equivalent secret-dependent value at the coordinator violates this contract.

## Abort and Leakage Rules

- A participant may abort before committing preprocessing without consuming it.
- Every abort after commitment burns the preprocessing record.
- Rejection outcomes are transcript-bound and cannot be retried with the same
  record.
- A coordinator cannot probe one committed record with multiple challenges.
- Complaint evidence is limited to values required to identify invalid public
  messages; it cannot include an honest participant's local witness.
- Timing, allocation, and branch behavior on secret values require a separate
  side-channel review before the audit-candidate stage.

## Reshare Consistency Transcript

Reshare consistency uses only linear projections and does not open recipient
share vectors. The transcript order is mandatory:

```text
contribution commitments
-> nonce commitments
-> nonce reveals
-> masked-term commitments
-> masked-term reveals
-> syndrome decision
```

The challenge nonce is the XOR of six committed nonce shares. Projection terms
are protected by fresh pairwise zero-sum masks derived outside the coordinator.
Masked terms use an additional 32-byte commitment salt so the small field value
cannot be brute-forced before the reveal phase. Reusing a nonce share, pairwise
mask domain, term salt, or consistency round identifier is forbidden.

The coordinator may learn only signed commitments, nonce reveals, masked term
reveals, and the final zero or non-zero syndrome. It must not receive an
unmasked projection, recipient contribution, old local share projection, or
pairwise mask.

## Simulator Obligations

A future proof or reduction must show that the view of the coordinator plus any
two corrupt participants can be simulated from:

- the public key and committee metadata;
- their own local shares and randomness;
- the message, context, and canonical session transcript;
- public abort decisions and complaint evidence;
- the final signature when signing succeeds.

The simulator must not require an honest local share, a complete nonce, the
complete signing key, or non-standard leakage from rejected attempts.

## Release Blockers

The following remain hard blockers for a production claim:

- a complete algebraic protocol for authenticated preprocessing;
- a proof or externally reviewable reduction for the stated corruption model;
- deterministic interoperability vectors for every MPC operation;
- active-adversary tests with two corrupt participants and a malicious
  coordinator;
- constant-time and memory-erasure review;
- a rollback-resistant external counter or append-only anchor for full-machine
  snapshot rollback.

Two further gates are external rather than development tasks, and are therefore
not tracked in this project's backlog: independent cryptographic review and
independent implementation audit. Both are future third-party engagements, and
until they complete no production claim may be made.

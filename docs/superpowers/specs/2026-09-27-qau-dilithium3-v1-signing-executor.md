# QAU Threshold Dilithium3 v1 Signing Executor: Network Design and Cost Finding

**Status:** Design note; defines the interactive executor layer and fixes one
open question that gates it. It does not enable anything.

**Date:** 2026-09-27

## Purpose

`2026-09-24-qau-dilithium3-v1-signing-mpc.md` fixes the arithmetic and the four
rounds of the threshold signing construction, and R53 landed the wallet-side
state machine as an in-process reference driver. That driver is scaffolding: it
drives all four signers in one process, holds a dealer, and prescreens the
randomness in the clear. Obligation 1 of that note is the missing production
layer: a **networked executor** that runs the same arithmetic across four
signer processes, carries the public round messages between them, and produces
attributable evidence when a slot aborts.

This note fixes the executor's shape and reports a **measured cost finding**
that gated one part of it: the literal rejection loop could not run over the
deployment network as specified. Section "Cost Reality Check" states the
numbers and their resolution: the R57 revision of the signing note replaced
that loop with per-party local rejection, and the executor section below is
the post-R57 shape.

## Where It Plugs In

The executor must reuse the conventions this repository already runs for
networked multi-party rounds. The reuse map, verified in the tree:

| Concern | Existing pattern to reuse |
|---|---|
| Message framing and canonical encoding | `wallet/tss/protocol/envelope.go`; the DKG message marshalling in `dilithium3v1/dkg_session.go` and `dkg_commitment.go` |
| P2P message types and validators | `p2p/message.go` reserves the `qau_tss` kinds `90..96` for Dilithium3 v1 DKG; `p2p/message_validator.go` routes them through `ValidateTDilithium3DKGEnvelope` and exempts them from the content-hash dedup that would swallow retransmissions |
| Sender authorization | the inbox pattern of `node/tdilithium3_dkg_inbox.go`: a per-session identity snapshot, an explicit recipient position, a replay key, and an admissibility gate checked before any message is delivered |
| Round driving, buffering, dispatch | `node/tdilithium3_dkg_group_round.go` (observe / advance / outbound with a signer callback) and `tdilithium3_dkg_group_network.go` (per-group exchange, dispatch, stall errors that name group and leader) |
| Durable single-use state | `wallet/tss/protocol/dilithium3v1/sign_journal.go` (`SingleUseRecord`, hash-linked, fail-closed on restart) and `preprocess.go` (`PreprocessingRecord`) |
| Wallet-side round messages | `protocol.SigningMessage{SessionID, SenderID, Sequence, Kind, Payload}` and `protocol.SigningAction{Outbound, FinalSignature, Complete, BurnSession}` in `protocol/backend.go` |
| Opaque secret handles and evidence | `MPCSession`, `SecretHandle`, `Evidence`, and the `MPCExecutor` interface in `dilithium3v1/mpc.go` |

New P2P kinds for signing-executor messages must be requested in the same
`qau_tss` block, registered with a validator that pins protocol, algorithm,
generation, session, and payload bounds, and exempted from content-hash dedup
for the same retransmission reason as the DKG kinds.

**Status after R57.** The executor shape, the roles and session binding, the
message-model requirements, the evidence and burn rules, and the node-wiring
slice all stand. Two sections are superseded by the signing note's R57
revision and are kept as history: "The Interactivity Inventory" now contains
only the round messages, because there are no blinded openings of share
arithmetic anymore, and "Preprocessing Supply" no longer applies, because the
revised construction samples its randomness online per slot. In the reuse map
above, the `SingleUseRecord` row stands and now binds the slot's committed
randomness; the `MPCSession` / `SecretHandle` row and the arithmetic-engine
dependencies are retired with the online MPC layer.

## Roles, Session, and Binding

- Four **signers** are peers. Each holds one `LocalShare`, its own ball
  randomness for the slot, its own partial secret, and its own single-use
  record.
- The **coordinator** routes messages and is untrusted: it may reorder, drop,
  duplicate, replay, or forge them, and it must never learn the raw
  randomness, a partial secret, or any second-half response. The executor must
  be correct against a malicious coordinator plus up to two corrupt signers.
- The **session** is `Dilithium3SigningSessionID(request, signerIDs)` and a
  **slot** is one session plus one committed randomness record. Every
  message carries the session identifier, the slot index, the sender, a
  strictly increasing sequence, and a kind; a message for another session,
  another slot, another generation, another committee, or another kind
  ordering is rejected before delivery.
- Aborts are bucketed by attribution: an inconsistent round-1 commitment, an
  inconsistent reveal, a response inconsistent with the committed randomness,
  a failed combine check, and a silence are separate reason codes, each
  recorded with the responsible participant position.

## Message Model Requirements

1. **Canonical, fixed-width encodings.** Every payload has one canonical byte
   encoding with a pinned length; the decoder rejects every non-canonical form,
   as the DKG and signature encodings already do.
2. **Attributable reveals.** Every revealed value carries the revealing
   party's identity signature over (session, slot, sequence, kind, payload),
   and an inconsistency must be attributable to a participant position. A
   failed check is a sticky abort that burns the slot.
3. **Whole-vector reveals.** The public reveals are whole polynomials or whole
   vectors (`w_i`, `z_i^(1)`), never scalar values. A scalar-granularity
   protocol would produce hundreds of thousands of messages per request.
4. **Deterministic replay handling.** Retransmissions are allowed and deduped
   by (session, sender, sequence, kind); a duplicate must be idempotent, not a
   second application.
5. **Fail-closed.** Missing messages, timeouts, and ordering violations stall
   the attempt with a bounded reason code; they never fall back to a different
   construction and never release a partial response.

## The Interactivity Inventory

*(Superseded by R57; kept as history. The revised construction's only
networked values are the round messages of the signing note: the commitment
digest, `w_i`, the acceptance bit, `z_i^(1)`, and the combine transcript.)*

Only three things in the whole construction need the network:

1. **Openings.** Additive shares plus MAC shares are broadcast and summed.
   Every multiplication pays two blinded openings; every mask decomposition
   pays one. These are the only values that leave a signer during the
   arithmetic.
2. **Supply.** The uniform decomposition masks and the Beaver multiplication
   triples. In the reference engine a dealer provides them; the executor
   consumes them from the signer's own single-use preprocessing record.
3. **Round messages.** The public transcripts of the four rounds: the round-1
   commitment digest, `w1` and `c_tilde`, the accepted aggregate `z`, and the
   final signature. These are exactly the artifacts
   `signingCommitment`/`signingChallenge`/`signingResponse` already carry.

Everything else — additions, scalings, the boolean circuits, the carry chains,
the high-bit formula, the comparisons — is local share arithmetic and must
never produce a message.

## Evidence, Abort, and Burn

- A **local rejection** is a normal outcome: the executor publishes only the
  acceptance bit and the reason code, burns the slot, and reveals nothing
  else. No rejected value may ever be broadcast, in any round.
- A **failed combine check** or an **inconsistent transcript** is
  attributable: evidence names the participant position and the disputed
  digest, and contains no raw randomness, no `z_i^(2)`, no partial secret, and
  no secret coefficient.
- A **restart** burns every unfinished session, as `sign_journal.go` already
  enforces; retrying creates a new slot with fresh randomness. No randomness
  is ever reused across slots or attempts.

## Preprocessing Supply

*(Superseded by R57; kept as history. The revised construction samples its
ball randomness online inside each signer for every slot; no masks, triples,
or offline supply are needed, and the single-use record binds the slot's
committed randomness instead of a preprocessing resource.)*

The executor consumes, per attempt, one committed `PreprocessingRecord` whose
contents are:

- one uniform mask with its bit sharing per coefficient decomposition;
- one Beaver triple per multiplication;
- all of it authenticated with the party's MAC key shares, and all of it
  single-use.

The reference engine's `dealerMask` and `dealerTriple` stand in for a
generation protocol that has not been written. Two candidate models, to be
decided in review:

- **A. Offline generation inside the DKG epoch.** The six-member committee
  generates supply with an honest majority (at most two corrupt of six), stores
  it per party in preprocessing records, and the four-signer attempt consumes
  it. This matches the existing single-use record lifecycle and keeps the
  online phase to openings only.
- **B. Per-attempt generation over the network.** Generating triples inside a
  four-signer set tolerates only half corruption, which requires a much
  stronger protocol than A. This is not recommended.

Either way, the supply is what makes the rejection loop affordable or not; see
the next section.

## Cost Reality Check

The numbers below are measured, not estimated. R52 pinned the per-circuit
counters; R53's `TestThresholdSigningAttemptCostEnvelope` now pins the whole
attempt.

**One accepted attempt** (all four rounds, one candidate nonce):

```text
challenge  324864 shared multiplications   658688 openings
respond    552958 shared multiplications  1111550 openings
total      877822 shared multiplications  1770238 openings
```

Prepare, commit, and finalize are public and cost nothing in the MPC.

**One accepted signature.** The design note's R53 correction fixes the joint
per-attempt acceptance rate of `P1` and `P2` at `2.9e-4`, about **3400
attempts** per accepted signature. Therefore:

```text
shared multiplications   877822 * 3400  ~= 3.0e9
openings                1770238 * 3400  ~= 6.0e9
```

At four parties and two four-byte values per opening (share plus MAC share),
that is on the order of **190 GB of authenticated share traffic per
signature**, before framing overhead. On a 1 Gbps link that is about 26
minutes of pure transport; on 10 Gbps, about 2.6 minutes. Latency is a second
independent bound: the circuit depth is a few hundred sequential
multiplications per attempt, so the literal loop needs on the order of `1e6`
sequential rounds per signature, hours at inter-validator round-trip times.
Batching many candidate nonces in parallel removes the latency bound but not
the volume bound.

The preprocessing supply is worse: one triple per multiplication means about
`3.0e9` triples per accepted signature, tens of gigabytes of stored supply per
party, regenerated for every signature. No offline phase can stockpile that.

**The design note's Cost Envelope understates this by about thirty.**
`2026-09-24-qau-dilithium3-v1-signing-mpc.md` says "roughly 5e5 shared ANDs per
attempt ... about 1e8 shared ANDs per signature". `5e5 * 3400` is `1.7e9`, and
the measured per-attempt count is `877822`, so the correct figure is about
`3e9` per signature. The conclusion of that section — that preprocessing
amortizes and the online phase is dominated by communication — does not hold
at this magnitude for a per-block finality signature; it does hold for a
rejection rate near the native one.

**Consequence (historical).** The executor layer could be built in part under
the retired construction, but the *literal* rejection loop could not be
enabled without either (i) removing `P2` from the MPC path, or (ii) changing
the nonce strategy.

### Resolution (R57)

Option 2 was authorized and landed as the R57 revision of the signing MPC
note. The revised construction publishes each signer's MLWE commitment share,
rejects locally with the per-party hyperball test, and evaluates the three
combine checks on public values. Consequences for this note:

- the `P1`/`P2` MPC circuits, the shared carry, and the entire preprocessing
  supply (masks and triples) are gone from the signing path; the online MPC
  layer this note was going to carry no longer exists;
- the executor's job shrinks to transporting public round messages, running
  the ball sampler inside each signer process, the acceptance bits, the
  accepted response parts, evidence, and the `J`-slot schedule;
- the cost question this section raised is answered by the signing note's
  parameter table: `J = 11` slots per request and `83808` bytes per party per
  request by the reference convention (about 69 kB on average with only
  accepted slots revealing responses), against `6123264` bytes per party for
  the reference's own `(4,6)` mode3 parameter set, and against the `190 GB`
  this section measured for the retired loop.

Options 1, 3, and 4 from the R56 review are closed: 1 stays rejected as
unproven, 3 is moot because the loop is gone, and 4 is superseded.

## Implementation Slices and Acceptance Criteria

The R57 revision removes the `P1`/`P2` circuits and the carry, so the schedule
below is the revised one: it contains no per-circuit-layer opening schedule and
no offline supply.

- **Slice 1: session, sampler, authorization, evidence, and the adversarial
  harness.** Wallet-side message kinds and canonical encodings for the four
  rounds (commitment digest, `w_i` reveal, acceptance bit, `z_i^(1)`, combine
  transcript); the uniform-ball sampler inside the signer process with its
  distribution test; an inbox-style authorization gate and replay table;
  evidence and abort reason codes; an in-process router that can reorder,
  drop, duplicate, replay, and forge messages. Acceptance: honest four-signer
  runs complete and match the reference driver's decisions on the same inputs;
  every injected deviation either completes or aborts with a bounded,
  attributable reason; two corrupt signers plus a malicious coordinator cannot
  make an honest signer publish a response for a rejected slot.
- **Slice 2: slot schedule and batching.** The `J`-slot request schedule with
  pinned per-slot message counts, verified against the reference driver by
  differential testing of every published value and every acceptance decision.
- **Slice 3: single-use binding and restart.** The committed randomness of each
  slot bound into the single-use record (the R51 lifecycle), with burn on every
  abort and no reuse across restarts. No offline supply generation is needed:
  the revised construction samples online per slot.
- **Slice 4: node wiring.** Finality and sealing behind the existing
  default-off gates, with the mainnet default unchanged and no fallback
  weakened. Blocked until slices 1 to 3 can sign end to end.

### Status after R61-R72c

Slices 1 to 3 have landed as local commits, and Slice 4 has landed its wire
framing:

- **R61** (`b6988a1`): the in-process executor driver and its adversarial
  routing harness. Four signer instances exchange the four public round
  messages through the R59 message layer and the R60 gate; every signer
  recomputes `w`, `w1`, and the challenge locally, evaluates its own rejection
  predicate locally, and releases its response part only when its own bit and
  every observed bit are true.
- **R62** (`86b7cd6`): the `J`-slot request schedule with pinned per-slot
  message counts (12 messages and 4671 bytes per signer for a locally rejected
  slot, 16 messages and 7881 bytes per signer for a slot whose local tests all
  passed) and value-by-value differential testing of every published value.
- **R63** (`fc6e36e`): the single-use binding. Every signer holds its own
  durable journal and one-time record, binds the slot's committed randomness
  before its first message leaves, and consumes the material on every path
  that does not end in a signature.
- **R64** (`d4e6dfd`): the `qau_tss` kinds 97 to 100 with their p2p validator
  and the content-hash dedup exemption.
- **R65** (`020dd05`): the node-side signed wire layer for those kinds.
- **R67** (`59a29c7`): the local-only derivation of a signer's partial secret
  (`localPartialSecrets`), cross-checked against the reference reconstruction.
- **R67b** (`15e58b8`): the exported per-signer party surface
  (`NewSigningExecutorParty`), a thin wrapper of the executor signer that holds
  one `LocalShare`, samples its own ball point inside the signer process, and
  exposes the bounded outcome of every delivery
  (`SigningExecutorOutcomeOf`). The differential tests drive four parties and
  the in-process session over identical slot inputs and require byte-identical
  emissions, the same outcome class, and the reference signature.
- **R68** (`304b107`): the node-side inbound half: the authenticated executor
  inbox (identity snapshot, source-peer binding, a sequence-keyed replay and
  equivocation table, verified wallet-kind messages on a bounded channel), the
  `tdilithium3SigningInbox` plumbing with its admissibility gate, and the
  `handleTSSMessage` routing of kinds 97 to 100.
- **R68b** (`8a84c32`): the node-side outbound half: the per-slot transport
  that assigns strictly increasing sequences, signs and broadcasts one envelope
  per round kind, and keeps each envelope for a byte-identical retransmission.
- **R69a** (`9b35929`): `SigningExecutorParty.Done`, the terminal-state query
  the driver needs: Finish is terminal and cannot be used to poll.
- **R69b** (`7ad31c4`): the inbox accepts fresh messages in any arrival order
  (the p2p transport reorders) and keeps the DKG-shaped replay rule keyed by
  `(sender, sequence)`; the sender still assigns strictly increasing sequences.
- **R69c** (`bf0586d`): the slot driver that binds one party to its transport
  and inbox: admissibility and deadline first, then start, install, pump,
  deliver, retransmit, and close once, with every path but a signature
  consuming the slot's one-time material.
- **R70a** (`467ff95`): the slot's one-time record is now mintable
  (`NewSigningExecutorRecord`, no offline supply) and the party classifies a
  legitimate filter (`Filtered`), which the schedule owns as its retry policy.
- **R70b** (`cdf6383`): the request schedule: up to `J` candidate slots, each
  with its own record, party, transport, inbox, and deadline; a filtered slot
  advances, every other failure ends the request, and all-filtered reports
  exhaustion with every outcome.
- **R71a** (`3af0659`): the roster-derived projections the finality adapter
  needs: the four signers' identity snapshot
  (`tdilithium3SigningIdentitiesForRoster`) and the share-store identity
  verifier (`tdilithium3SigningShareVerifier`), both read from the captured
  epoch roster and never from the live validator set.
- **R71b** (`3c94e86`): the binding assembly and the signing entry point:
  `newTDilithium3SigningBinding` loads the active share for the activation epoch
  through the roster verifier and the validator key password, checks the share
  against the roster's committee, position, and epoch, binds the local validator
  key (D6), builds the signers' peer snapshot, and opens the request-long
  journal under the share's own directory; `request` and
  `signWithTDilithium3Signing` turn a message into a full request and run the
  request schedule. Its happy path needs a p2p host, a block producer, a
  captured roster, and a stored share, so the development network integration
  covers it; every reachable missing or mismatched input fails closed.
- **R72a** (`2bae82a`): the request nonce is derived, never drawn.
  `SigningRequestAttemptNonce` computes it from the chain, epoch, slot, domain,
  message digest, and attempt ordinal, so the four signers of one attempt derive
  one session from public inputs alone. R71b drew it from the local entropy
  source, which would have produced four different session identifiers and no
  networked session at all; the session identifier hashes the nonce and the
  envelope layer requires one session across the four signers.
- **R72b** (`5831c73`): the seal-side wiring (decision C, below): the node
  signs at the pending seal it holds instead of routing the executor through
  `ThresholdKeySigner`, so the consensus interface and every mock stay
  untouched. `consensus.QTDSignedMessage` exports the message construction;
  `ActiveSharePublicIdentity` reports the share's activation epoch as the hint
  the roster derivation needs; the fixed four signers are the first four
  committee positions; a higher announced ordinal cancels the running attempt;
  one node runs one session at a time; and `qfs.SubmitCompletedSeal` verifies
  the produced signature against the epoch's group key.
- **R72c** (`f835dc4`): the finality surface. The adapter reports the v1
  threshold shape (4), the epoch group key, and plain Dilithium3 verification,
  and refuses every single-signer operation. Registration binds exactly one
  activation epoch through `qfs.SetQTDSignerForEpoch` -- the QPOS-level block
  and vote signing path is untouched -- and a gated startup refresh binds the
  surface from an already installed share.

### Decision Record (R72): the Adapter Shape

The seal flow collects partial seals and aggregates with
`AggregatePartialSignatures(sealers, partialSigs, message)`, which carries no
epoch and no slot; the executor instead signs in one interactive four-round
session whose request binds chain, epoch, slot, domain, and the attempt ordinal.
Three shapes were weighed (extend the interface with a seal context; give the
adapter a slot/epoch provider; drive the session where the pending seal is
known), and the third was chosen:

- the seal site (`computeAndCompleteQTDSeal`) already holds the slot, the block
  hash, and -- through the pending seal -- the epoch and the chain, so no
  interface has to carry them;
- `consensus.ThresholdKeySigner` and its implementations and mocks stay
  untouched, and the legacy path stays byte-for-byte unchanged while the gate is
  closed;
- the submission path (`qfs.SubmitCompletedSeal`) already verifies the produced
  signature against the epoch's group key, so the executor is never trusted by
  the finality layer.

Two further decisions came with it. The attempt ordinal is part of the request
nonce and is announced by the slot's proposer (the existing proposer check on
the seal request is the ordinal authority), because only one authority can keep
four signers from drifting into different attempt numbers. The signers are the
fixed first four committee positions (participants 1 to 4, roster positions 0
to 3), which is deterministic on every node with no extra round; a rotation of
the subset can come later without touching the session binding.

**Slice 4 remains incomplete** in exactly one place: the development-network
integration of the full path (four real shares, four p2p hosts, a live seal
window), plus the production activation wiring that installs the share and
registers the surface from the DKG ceremony. Known bounds, recorded rather than
hidden: a retry is paced only by a proposer that is itself one of the four
signers, so a slot proposed by a validator outside the four runs a single
attempt; the active share is read twice per attempt (epoch hint plus verified
load), both through the share store's scrypt-based persistence path; and while
the gate is open the QTD verification surface no longer routes through the
legacy TSS verifier, so re-verification of pre-experiment finality records on
that node is a development-network concern.

### Status after R73 (R73A/R73B)

- **R73a**: the activation exchange is wired into the ceremony, with the
  convergence mechanism of the session-derivation spec (§6.1): the committing
  node gossips the self-verifying certificate (message type 101) in a bounded
  burst, peers adopt it fail-closed through `ActivateCandidate`, and both the
  ceremony and a running exchange short-circuit once the share store reports
  the epoch's active share. The exchange rebroadcasts its own acknowledgement
  on a one-second ticker so staggered node starts still collect the full set.
- **R73b**: the concurrency fixes the development network exposed. The request
  schedule runs its candidate slots concurrently (serial evaluation let nodes
  drift onto different candidates and wait out each other's timeouts; the slot
  timeout rose to 15 s to cover the proposer head start plus four rounds), the
  signing inbox is keyed by session id so concurrent candidate sessions route
  their own round messages, the signing journal is a node-level shared cache
  (bbolt holds an exclusive file lock), and the seal executor admits up to
  eight concurrent slots (`tdilithium3SealSigningMaxConcurrentSlots`). The seal
  path gained a `QAU_TRACE_TDILITHIUM3_V1_SEAL` trace switch with branch-level
  logging on every fail-closed gate.
- Three wiring bugs the same network run exposed are fixed: `GetPendingSeal`
  now carries the `ChainID`/`Epoch` domain-separation tuple the executor signs
  (R39-P0-01; a zero tuple made the executor refuse the seal as a legacy
  record); the epoch-transition DKG trigger now opens for the v1 backend when
  the gate is open (`v1OwnsActivation`), where the legacy non-empty group key
  gate made the v1 ceremony unreachable; and the randomness round resumes from
  the journal instead of requiring a freshly prepared runner.
- The seam test drives the full path end to end in one process: a real
  six-node DKG ceremony, share-store reload, and the production request
  schedule over the real transport, inbox, and p2p routing, with every
  negative case failing closed. Node-level adoption tests cover the gossip
  path: malformed payloads, forged acknowledgements, a certificate without the
  candidate share, an underivable session, a live inbox of another epoch, and
  idempotent re-adoption.
The strict-bootstrap revert of R73 concluded before a full devnet run existed.
The R74 devnet run (below) surfaced the real boundary behaviour the relaxed
rule had been written for: under `<=`, the roster epoch used by the first
eligible activation (epoch 2, roster epoch 1 = the bootstrap boundary on a
fresh chain) is refused forever by nodes that captured that boundary while
applying their own blocks. R74 re-applies the relaxation — `lookup` and
`lookupCaptured` now serve the bootstrap boundary itself and refuse only
strictly-below epochs — with a reasoned write-up in the session-derivation
spec ("Bootstrap rule revision (R74)") and the five pinned tests updated to
the new boundary.

### Devnet acceptance run (R74)

Six-process devnet, chain id 1333, both gates open, `tssDistributedDKG` true,
full-mesh bootstrap topology (the earlier star topology left the non-bootstrap
nodes without peer bindings for some committee members, which is the inbox's
fail-closed identity gate working as designed), fresh chain data and a fresh
genesis timestamp:

- Epochs 0 and 1 fail closed by design: activation epochs below 2 have no
  lower boundary to anchor on (D1).
- Epoch 2 completes on **all six nodes** with cross-process agreement: one
  session (`2fad5ca13968c0fb`), one transcript (`f43b4ca55a8bd2f8`), one group
  key (`9bcefef3f2f55c68`), six
  `Dilithium3 v1 DKG ceremony completed` lines followed by six
  `GOV- executive chamber activated for epoch 2 via distributed DKG` lines
  with no legacy variant, each within ~60 s of the epoch boundary.
- After activation the seal executor drives QTD finality forward on the live
  chain: block production logs show `justified` and `finalized` advancing
  epoch by epoch (e.g. epoch 4 head logs `justified=3 finalized=2`). The only
  seal-request rejections observed are transient `B-5` rejects for orphan
  seal requests sent by the node whose block lost the epoch-2 activation
  race, which is the gate's intended refusal.

This run is the closing acceptance evidence for Slice 4; the "what still
remains" paragraph above is retired by it.

The verified sources the binding assembly uses, for reference:

| Input | Source (existing node API) |
|---|---|
| roster epoch | `tdilithium3DKGSessionRosterEpoch(activationEpoch)` = `activationEpoch - 1` |
| roster | `n.capturedEpochValidatorRoster(rosterEpoch)` (finalized-epoch sidecar) |
| committee | `n.tdilithium3DKGCommitteeForRoster(roster)` (same derivation the activation used) |
| active share | `newThresholdShareStore(n.config.DataDir).LoadActiveAtEpoch(activationEpoch, verifier, []byte(n.config.ValidatorKeyPassword))` |
| identity signer | `n.blockProducer.ValidatorKey().Sign` (the key the roster publishes, D6) |
| broadcast | `n.p2pHost.BroadcastTSS` |
| peer bindings | self-bound closure over `n.p2pHost.GetPeerIDForValidator` (ceremony pattern) |
| signing journal | `dilithium3v1.OpenSigningJournal` under the share's own `newThresholdProtocolPaths` root |

R72b and R72c added two more node-side inputs to the same assembly: the
attempt ordinal announced by the slot's proposer, and the active share's public
identity (`ActiveSharePublicIdentity`, the epoch and group key in one read) that
both the binding assembly's roster hint and the finality surface registration
consume. Together with the development-network integration of the production
factory against a real DKG share, these are the remaining Slice 4 items; see the
wire framing section and the open obligations below.

## Signing Executor Wire Framing (Slice 4)

The four round messages travel inside the shared threshold envelope
(`wallet/tss/protocol/envelope.go`) on the p2p kinds `97..100`, one kind per
wallet-side round message. The envelope fields are exactly the ones the message
model requires:

| Envelope field | Signing executor binding |
|---|---|
| `Protocol`, `Algorithm` | `ThresholdProtocolDilithium3V1`, the legacy Dilithium3 profile |
| `MessageType` | 97 commit, 98 reveal, 99 acceptance, 100 response |
| `KeyGeneration`, `CommitteeVersion` | the signing request's key generation and committee version |
| `SessionID` | `Dilithium3SigningSessionID(request, signerIDs)` |
| `SenderID` | the sending signer's participant identity, one of the four |
| `Sequence` | per sender, non-zero, strictly increasing for fresh messages; a retransmission reuses its envelope byte for byte |
| `Payload` | the canonical R59 round payload; the slot index lives inside it |
| `IdentitySignature` | the sender's Dilithium3 identity signature over the envelope signing bytes |

The slot index deliberately stays inside the payload: the wallet-side decoder
already pins it, and a second copy in the envelope could disagree with its own
encoding. Inbound order is therefore: p2p structure and canonical payload
(R64), envelope context and sender membership (R65), identity signature (R65),
then the executor gate on `(sender, slot, kind)` (R60) before any state is
touched.

The receiving node dedupes on `(sender, sequence)`: an identical envelope is an
idempotent duplicate, a second, different payload for a used sequence is a
conflict, and fresh envelopes are accepted in any arrival order. Ordering is
deliberately not enforced there (R69b): the p2p transport reorders, the party's
gate is the ordering-sensitive layer, and a receiver-side monotonic rule would
turn a reordered broadcast into a persistent refusal until the slot burns.

Attempts are announced, not negotiated (R72b). The seal request notification
carries the slot and the block hash; a retry appends an eight-byte attempt
ordinal, so the legacy 40-byte payload is a first attempt and an extended
payload names a later one. The receiver's existing check that the sender is the
slot's proposer authenticates the announcement, which makes the proposer the
only ordinal authority -- the one shape that keeps four signers from drifting
into different attempt numbers. A node that is one of the four fixed signers
(committee participants 1 to 4, roster positions 0 to 3) starts the announced
attempt, cancels a lower-ordinal attempt it is still running, and submits a
produced signature through `qfs.SubmitCompletedSeal`, which verifies it against
the epoch's group key; a node outside the four only announces. The finality
surface is the R72c adapter: the v1 threshold shape, the epoch group key, and
plain Dilithium3 verification, with every single-signer operation refused.

A production signer runs a **per-signer** surface: it holds one `LocalShare`,
its own randomness, its own journal, and its own record, and it emits and
consumes the four messages through the inbox. That surface is
`NewSigningExecutorParty` (R67b): it binds one signer's slot, samples the ball
point inside the signer process, exposes `Start`/`Drain`/`Deliver`/`Finish`,
and reports every deviation as a bounded `SigningExecutorOutcome`. The
in-process drivers of `sign.go` and `sign_executor.go` hold all four shares and
therefore stay references; they must never be the object a node drives.

Nothing here enables the executor. The node wiring must sit behind the existing
default-off gates (`QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1` and friends), keep
the mainnet default unchanged, and weaken no fallback.

No production path may depend on the reference driver in `sign.go`; the driver
stays the behavioral oracle that the executor is differentially tested
against. `mpc_arithmetic.go` is retired from the signing path (signing note,
Open Obligations item 8).

## Open Questions for Review

1. ~~Is the per-party local rejection revision authorized?~~ **Authorized and
   landed (R57).** The schedule follows the revised construction: no
   per-circuit-layer openings and no offline supply.
2. ~~Which preprocessing supply model is chosen, A or B?~~ **Dissolved by
   R57.** The revised construction samples its randomness online per slot, so
   the signing path needs no offline masks or triples; the single-use record
   binds the slot's committed randomness instead of a preprocessing resource.
3. ~~May new `qau_tss` P2P kinds be reserved for the signing executor in the
   same block as the DKG kinds?~~ **Reserved and landed (R64/R65).** Kinds 97
   to 100 are registered with a validator that pins the envelope context and
   the canonical round payload, and they are exempt from content-hash dedup
   for the same retransmission reason as the DKG kinds.
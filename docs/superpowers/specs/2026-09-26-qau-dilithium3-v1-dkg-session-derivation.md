# QAU Dilithium3 v1 DKG — Session Derivation and Node Wiring Design

**Status:** Approved and implemented. The node wiring, the ceremony orchestrator
and the verification plan below are in the tree; the gates stay default-off and
no `consensus/` file was touched. The wiring is confirmed end-to-end on a
six-process devnet (section 7).

**Date:** 2026-09-26

**Extends:** `2026-09-24-qau-dilithium3-v1-cnf-rss-design.md` (the CNF-RSS design
fixes the construction; it leaves open where a production node obtains a
`DKGSession` and who calls the ceremony).

**Scope:** node layer only (`node/`). No `consensus/` change is proposed here.

## 1. Problem

The CNF-RSS construction, the four-of-six topology, the twenty groups, the
journal, the encrypted share store, the authenticated envelope helper and the
epoch roster snapshot are all implemented and tested. The v1 ceremony is still
unreachable from a running node, because every entry point is constructed only
from tests.

| Artifact | Production caller | Evidence |
|---|---|---|
| `tdilithium3DKGInbox` assignment | none (always `nil`) | `node/node.go:242` field; every assignment is a test struct literal |
| `DKGSession` value | none | no non-test `dilithium3v1.DKGSession{...}` construction |
| `newTDilithium3DKGRunner` | none | only `_test.go` callers |
| `runTDilithium3DKGRandomness` | none | only `_test.go` callers |
| `runTDilithium3DKGGroup` | none | only `_test.go` callers |
| `tdilithium3DKGFinalize` | none | only `_test.go` callers |
| `newTDilithium3DKGInboxFromCapturedEpochRoster` | none | only `_test.go` callers |
| `tdilithium3DKGEpochRosterBindings` | none | only `_test.go` callers |
| epoch roster capture | **wired** | `node/block_producer.go:3367`, `node/node.go:7660`, `node/node.go:8937` |

The last two rows are the asymmetry: the roster snapshot is written on every
block-apply path but has no production reader. The ceremony has twenty groups
of tested machinery and no production trigger. This document closes both.

## 2. Scope and Non-Goals

In scope:

- deriving a `DKGSession` deterministically from chain state and the roster snapshot;
- a production ceremony orchestrator (randomness round, twenty group rounds, finalize);
- wiring the ceremony behind the existing experimental gates;
- assigning `Node.tdilithium3DKGInbox` so inbound v1 messages reach the ceremony.

Out of scope, unchanged:

- online threshold signing, same-key reshare, epoch rotation rewards;
- group leader replacement (still requires verifiable complaint rules);
- any change to the default-off gates;
- any `consensus/` change (an optional one is listed in section 9).

## 3. Decisions

Each decision is marked **APPROVAL** where it changes observable behavior or
fixes a rule that has no obvious default.

### D1 — Roster epoch for a session **APPROVAL**

`DKGSession.ActivationEpoch` is the epoch the produced key activates for. The
identity roster is read from `ActivationEpoch - 1`.

Why not `ActivationEpoch`: the epoch roster is captured while applying the
boundary block of that epoch (`node/tdilithium3_dkg_epoch_roster.go:486-526`),
and `lookup` refuses an epoch that is not finalized
(`node/tdilithium3_dkg_epoch_roster.go:358`). The Three Chambers transition
fires the runner while entering epoch `N`, at which point epoch `N`'s boundary
is applied but almost certainly not finalized. An exact-match rule would refuse
every session.

Why `ActivationEpoch - 1` is deterministic: the boundary block of `N-1` is an
ancestor of the head when epoch `N` begins, so every node at the same head
reads the same boundary hash and the same active validator set, and therefore
the same roster digest. `capture` already refuses to replace a finalized
epoch's boundary and lets a not-yet-finalized epoch be replaced by the newer
canonical boundary (`node/tdilithium3_dkg_epoch_roster.go:281-295`), so a reorg
before finality is handled by the existing code.

Consequence to accept explicitly: the DKG session binding is **captured-boundary
anchored, not finality-anchored**. Two nodes at different heads can derive
different rosters; that is a Round 0 identity-roster digest mismatch and the
session fails closed, exactly as the roster snapshot's own contract states
(`node/tdilithium3_dkg_epoch_roster.go:40-42`). Finality-anchored binding would
need the consensus accessor in D2-alt / section 9.

Implementation shape: add `capturedEpochValidatorRoster(epoch uint64)` that
returns the captured roster without the finality gate, keeps the bootstrap
refusal (originally `epoch <= bootstrap`; revised to `epoch < bootstrap` by
the R74 rule below, which makes the first-captured boundary itself servable),
and leave `finalizedEpochValidatorRoster` untouched for any other consumer. `tdilithium3DKGEpochRosterBindings` takes the
roster epoch explicitly instead of using `session.ActivationEpoch` directly.

Rejected alternative: relax `lookup`'s finality gate in place. That would
weaken the guarantee for every future consumer of that function, not just the
DKG session.

### D2 — Committee source and participant IDs **APPROVAL**

The committee is the roster, in canonical (ascending address) order, and
participant IDs are `position + 1`:

```go
Committee: protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
```

This already matches what `tdilithium3DKGEpochRosterBindings` asserts: it pairs
`session.Committee.Participants[position]` with `roster.Entries[position]` and
commits that pairing in `DKGIdentityRosterDigest`
(`node/tdilithium3_dkg_validator_snapshot.go:86-101`). Building the committee
any other way would make the pairing depend on state outside the snapshot.

The roster must contain exactly six entries. A different size fails closed
(`node/tdilithium3_dkg_validator_snapshot.go:82-85`); there is no subsetting,
because the committee-selection rule is consensus state and is not reproduced in
the node layer.

Note on the existing convention: the legacy TSS path treats a participant ID as
a 1-based index into the **live** validator set
(`node/tss_dkg_coordinator.go:148-183`, `node/tss_distributed.go:468-479`). The
v1 path deliberately does not use it. Reason: the live validator set is
mutable, epoch-untagged state, which is the exact problem the finalized-epoch
snapshot exists to solve. The v1 path stays self-consistent because it supplies
its own peer resolver derived from the roster (D5) and because the v1 inbound
path never calls `validateSenderParticipantID`.

One consequence to state plainly: a validator set with more than six active
members cannot run v1 DKG under this rule; such a chain fails closed until a
consensus accessor exists (section 9).

The `threshold` and `total` arguments the consensus caller passes are **not**
the v1 committee shape and are not compared against it. They describe the
executive chamber: `consensus/provinces.go:458-460` reads
`executive.Threshold()` and `len(executive.Members())`, and the executive
chamber is sized to `clamp(n/3-1, 1, 3)` with its threshold clamped to the
member count once `SetMembers` runs (`consensus/provinces.go:344-357`,
`consensus/shangshu_committee.go:137-143`), so it is never four-of-six on any
chain — the local devnet reaches the runner with one-of-one. The legacy branch
ignores the same arguments for the same reason: it returns the already
established `tssManager` group key. The shape the v1 construction must match is
the epoch roster, and that is enforced by the six-entry rule above. An earlier
revision of this document's implementation added a runner gate comparing the
two shapes; it was retracted (R43-DKG-CHAMBER-RETRACT) because it made the v1
branch unreachable in production.

### D3 — Nonce derivation and restart semantics **APPROVAL**

The nonce is derived, not agreed by messages:

```text
nonce = SHA256(
    "QAU-TDILITHIUM3-V1-DKG-SESSION-NONCE" ||
    chainID || genesisHash || keyGeneration || activationEpoch ||
    committeeDigest || identityRosterDigest
)
```

Every node computes the same nonce with no extra round, and a restarted node
recomputes it. This is required, not merely convenient: the journal path is
keyed by the session digest
(`node/tdilithium3_dkg_runner.go:195`) and `journal.Load(sessionDigest)` refuses
a mismatched digest (`node/tdilithium3_dkg_runner.go:205-209`), so crash
recovery only resumes if the same session is reconstructed.

Freshness comes from the inputs, all of which are chain-anchored: the roster
digest for the epoch, the activation epoch, and the key generation (D4). A
different epoch, a different validator set or a different chain yields a
different session, and the session digest is bound into every envelope and
every group seed.

Interaction with the CNF-RSS design, which currently says *"Restarting uses a
new session identifier and new contributions"*
(`2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`, "Round 1: Public
Randomness"): that sentence must be replaced, because it contradicts
crash-resume. Proposed replacement wording, to be applied on approval:

> An aborted attempt advances the key generation, which produces a new session
> identifier and new contributions; the aborted attempt's randomness and group
> seeds are never reused. Crash recovery of an in-flight attempt reuses the same
> session identifier and the same per-participant randomness, both of which are
> journaled, so a restarted node rejoins the attempt it was already in.

Rejected alternative: random broadcast nonce with a commit round. It needs the
agreed nonce durably stored before any seed is sent, which the journal does not
model, and it adds a round that buys nothing that the chain-anchored inputs do
not already provide.

### D4 — Key generation

`KeyGeneration = ActivationEpoch`.

Interim and deliberately simple: it is deterministic, unique per epoch, and
needs no consensus change. Combined with D3, an aborted attempt is not retried
inside the same epoch; the chamber stays in its DKG-running state and the next
epoch derives a new session. A consensus-backed generation counter is the
follow-up once reshare exists (section 9), and is a one-line change here.

### D5 — Peer binding

```go
// The host's validator->peer registry is populated only from signature-verified
// status messages received from REMOTE peers, so a node never has a binding for
// its own validator address. Bind self explicitly to the host's own peer ID:
// the whole committee -- self included -- is required both by the private-send
// target map and by the inbox identity snapshot. The self entry is never a send
// target, because the only private message (the group seed) is emitted by the
// group leader to the members except itself (outboundSeedLocked), so a node can
// never address a private message to itself.
ownAddress := roster.Entries[position].Address
ownPeer := n.p2pHost.ID()
peerForValidator := func(address types.Address) (p2p.PeerID, bool) {
    if address == ownAddress {
        return ownPeer, ownPeer != ""
    }
    return n.p2pHost.GetPeerIDForValidator(address)
}
```

Fail-closed: `newTDilithium3DKGInboxFromCapturedEpochRoster` rejects the
session if any committee member has no peer binding
(`node/tdilithium3_dkg_validator_snapshot.go:43-46`). There is no wait-for-peers
loop and no broadcast fallback for private group seeds. Liveness is provided by
the existing per-epoch retry (the coordinator logs the failure and leaves the
chamber pending), not by relaxing the binding.

### D6 — Identity signing key

```go
sign := func(message []byte) ([]byte, error) {
    return n.blockProducer.ValidatorKey().Sign(message)
}
```

`encodeTDilithium3DKGSignedEnvelope` already enforces the 3293-byte signature
size and the `"QAU-THRESHOLD-ENVELOPE-IDENTITY-V1"` domain
(`node/tdilithium3_dkg_authenticated.go:57-67`).

This decision carries an assumption that must be tested, not assumed: the local
validator key must be the key whose public bytes appear in the epoch roster for
this node's address. If they differ, every peer rejects this node's envelopes
and the session fails closed. A test asserting
`roster entry for my address .PublicKey == blockProducer.ValidatorKey().Public().Bytes()`
is part of the verification plan (section 7).

### D7 — Trigger, call site and the message loop

Trigger: the existing Three Chambers distributed-DKG call, unchanged on the
consensus side. `ThreeChambersCoordinator` already invokes the injected runner
off-lock on the epoch transition
(`consensus/provinces.go:467-468`, runner injected at `node/node.go:6775`).

New call site: `nodeConsensusDKGRunner.RunDistributedDKG`
(`node/tss_reshare_runner.go:29`, currently returns the legacy group key). The
v1 branch runs the ceremony on the calling goroutine, under a bounded context,
following the `reshareRunTimeout` precedent (`node/tss_reshare_runner.go:19`).
It returns the assembled 1952-byte mode3 public key, which is exactly what
`setDKGCompleteForEpoch` expects.

Message loop chicken-and-egg: `tssProcessingLoop` starts only when
`n.tdilithium3DKGInboundAllowed()`
(`node/node.go:6744-6747`), and that predicate requires a non-nil, roster-bound
inbox (`node/tdilithium3_dkg_inbox.go:129-144`). At startup the inbox is nil, so
the loop would never start and the ceremony could never receive a message.
Minimal fix: add `experimentalTDilithium3V1Enabled()` to the loop's start
condition. Authorization is otherwise unchanged: the accept path resolves the
inbox once through `tdilithium3DKGInboxSnapshot()` and then applies
`tdilithium3DKGInboxAdmissible(inbox)`, which keeps every check of the former
`tdilithium3DKGInboundAllowed()` (roster bound, non-mainnet, chain match, both
gates open). Inbound v1 messages are therefore dropped until the ceremony
installs the inbox, which is the correct behavior (dropping is safe; the rounds
retransmit on their ticker, and the inbox replay window is per
`(type, sender, sequence, group, attempt)`).

The ceremony must assign `n.tdilithium3DKGInbox` before its first broadcast, and
clear it when the ceremony ends, so that
`tdilithium3DKGInboundAllowed()` never reports an inbox belonging to an
abandoned session. Serialization excludes two concurrent ceremonies on one node:
the epoch transition is already the only caller and `runTDilithium3DKGGroup`
fails on a session digest mismatch, but an explicit guard (reject a second
ceremony while one is active) is cheaper to reason about than relying on it.

### D8 — Backend selection and no fallback

```text
if v1 selected  -> run the v1 ceremony; on failure return the error
else            -> existing legacy path, unchanged
```

Selection is explicit and evaluated before any work:

```text
v1 selected  ==  experimentalTDilithium3V1Enabled()
             &&  config.NetworkID != MainnetNetworkID
             &&  TDilithium3V1 priority over the legacy group key
```

A failed v1 ceremony must never return the legacy group key. Falling back would
silently activate the executive chamber with a key that no v1 participant holds
shares for, which is worse than failing. `selectThresholdBackendKind` already
takes this position for the signing path ("fallback is forbidden",
`node/threshold_backend_selection.go:56`); the DKG runner must match it.

The runner side is only half the rule, and on its own it is not sufficient. The
epoch transition is the other half: `ensureEpochStateForBlock`
(`node/block_producer.go`) hands `coordinator.TransitionExecutiveForEpoch` the
legacy `qpos.GetGroupPublicKey()` at every boundary, and
`TransitionExecutiveForEpoch` reads a non-empty key as proof that DKG has
finished — it calls `executive.SetDKGComplete(key)`, moving the chamber to
`ExecutiveActive` (`consensus/provinces.go:1079`). On the next tick
`CompleteDKGViaDistributedRunner` returns early on its `executive.IsActive()`
check and never calls the runner at all. A one-member executive chamber, which
is what `clamp(n/3-1,1,3)` produces on six validators, makes that terminal: the
rotation rule only fires for `len(newIDs) >= 2`, so the chamber is never
re-created and stays Active from the first boundary onward. The runner's
no-fallback rule is then satisfied in form while the v1 branch is unreachable in
practice.

So the transition must withhold the legacy key while v1 owns activation:

```text
withhold the key  ==  config.NetworkID != MainnetNetworkID
                  &&  experimentalTDilithium3V1Enabled()
```

The identical predicate the runner uses to select the v1 branch, so the two
decisions cannot drift apart. `groupPublicKey` is forced to nil and the
transition takes its documented "DKG pending - group public key not available,
will retry" path (`consensus/provinces.go:1022-1025`), leaving the chamber in
`ExecutiveDKGRunning` with its members selected — exactly the state the v1
ceremony activates from. A nil key never reaches `SetDKGComplete`, so the
transition is not a second activation authority once v1 is selected.

With the gates closed, or on mainnet, the predicate is false and the legacy key
is passed exactly as before: this is a wiring change on the experimental path
only, and no `consensus/` file is touched.

### D9 — Gating boundary

- The gate stays default-off: `QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1`
  (`node/threshold_backend_selection.go:23-29`).
- Mainnet is permanently excluded: `tdilithium3DKGInboxAdmissible()` refuses
  `MainnetNetworkID` (`node/tdilithium3_dkg_inbox.go:134-140`).
- The roster capture hook keeps its first-line gate check
  (`node/tdilithium3_dkg_epoch_roster.go:487`), and every new ceremony entry
  point repeats the same check, so a gates-closed node does no extra work and
  writes no extra file.
- No new goroutine is added to `startServices`; the only startup change is D7's
  extra condition on an existing loop.

## 4. Interfaces

New node-layer functions. Names follow the file's existing
`tdilithium3DKG…` convention.

```go
// Session derivation. Pure: same chain state + same roster -> same session.
func (n *Node) deriveTDilithium3DKGSession(activationEpoch uint64) (dilithium3v1.DKGSession, error)

// Roster access without the finality gate, bootstrap refusal kept (D1).
func (n *Node) capturedEpochValidatorRoster(epoch uint64) (*tdilithium3DKGEpochRoster, error)

// Committee + position for the local node, from the roster alone (D2).
func (n *Node) tdilithium3DKGCommitteeForRoster(roster *tdilithium3DKGEpochRoster) (protocol.CommitteeID, uint8, error)

// Ceremony orchestrator: inbox install, randomness round, twenty group rounds,
// finalize, inbox teardown. Returns the assembled 1952-byte public key.
func (n *Node) runTDilithium3DKGCeremony(ctx context.Context, activationEpoch uint64) ([1952]byte, error)

// Race-free inbox access (D7). The ceremony goroutine installs and clears the
// inbox while the TSS loop reads it, so the field is never touched directly, and
// the accept path authorizes the same snapshot it delivers from.
func (n *Node) tdilithium3DKGInboxSnapshot() *tdilithium3DKGInbox
func (n *Node) installTDilithium3DKGInbox(inbox *tdilithium3DKGInbox)
func (n *Node) tdilithium3DKGInboxAdmissible(inbox *tdilithium3DKGInbox) bool

// True when the v1 ceremony, not the legacy group key, owns executive-chamber
// activation for an epoch (D8). The epoch transition uses it to withhold the
// legacy key; the runner uses the same predicate to select the v1 branch.
func (n *Node) tdilithium3V1OwnsExecutiveActivation() bool
```

Existing functions reused: `tdilithium3DKGActiveRosterEntries`, and
`tdilithium3DKGEpochRosterBindings` /
`newTDilithium3DKGInboxFromCapturedEpochRoster`, which now take the D1 roster
epoch as an explicit parameter instead of reading it off the session. Also
reused: `newTDilithium3DKGRunner`, `runTDilithium3DKGRandomness`,
`runTDilithium3DKGGroup`, `tdilithium3DKGFinalize`,
`encodeTDilithium3DKGSignedEnvelope`.

`runTDilithium3DKGCeremony` needs two outbound closures, both thin wrappers over
the existing p2p host:

```go
broadcast      func(messageType uint8, payload []byte) error
sendPrivate    func(messageType uint8, recipientPosition uint8, payload []byte) error
sequence       // per-sender monotonic, nonzero; the replay window is keyed on it
```

## 5. Orchestration Sequence

1. `RunDistributedDKG(epoch, threshold, total)` selects v1 (D8) and calls
   `runTDilithium3DKGCeremony(ctx, epoch)`.
2. Derive the session (D3, D4): read the `epoch-1` roster (D1), build the
   committee and the local position (D2), hash the roster, compute the nonce.
3. Build the inbox from the roster and the peer resolver (D5), assign
   `n.tdilithium3DKGInbox`, log the session digest prefix.
4. `newTDilithium3DKGRunner`; the journal resumes an in-flight attempt or
   creates a fresh record.
5. `runTDilithium3DKGRandomness` — commit and reveal, all six contributions.
6. For each of the twenty canonical groups in order:
   `runTDilithium3DKGGroup` with a shared `tdilithium3DKGGroupExchange` so
   messages for not-yet-driven groups are retained rather than dropped.
7. `tdilithium3DKGFinalize` — assemble the mode3 public key, install the local
   ten-component share, persist the acknowledgement. Idempotent by construction.
8. Clear `n.tdilithium3DKGInbox` and return the public key.

## 6. Failure Semantics

| Condition | Outcome |
|---|---|
| Gates closed, or mainnet | Legacy path, byte-for-byte unchanged |
| Roster missing, at/below bootstrap, or not six entries | Fail closed with `errTDilithium3DKGEpochRosterUnavailable`; chamber stays pending |
| Local identity key differs from the roster entry | Peers reject this node's envelopes; session fails closed |
| Any committee member has no peer binding | Session refused before any message is sent |
| A group stalls, or the context deadline passes | `errTDilithium3DKGGroupStalled`; no partial transcript is written |
| Peer disagreement on the roster digest | Round 0 envelope rejection, session fails closed |
| Ceremony fails | Return the error; never substitute the legacy group key (D8) |
| Activation certificate from gossip, wrong session digest | `ActivateCandidate` epoch/session guard rejects; adoption skipped |
| Activation certificate from gossip, no matching candidate share | `VerifyCandidate` fails; adoption skipped |
| Duplicate activation certificate (re-adoption) | Idempotent short-circuit via stored-certificate byte-compare |

The coordinator's existing handling applies unchanged: it logs the failure and
leaves the executive chamber in its DKG-running state
(`consensus/provinces.go:469-473`).

### 6.1 Activation Certificate Convergence (Gossip + Adoption)

The activation exchange is unanimous (6-of-6 acknowledgements) and per-epoch
(D4: `keyGeneration = activationEpoch`). A node that finishes its exchange first
clears its activation sink (`defer clearTDilithium3DKGActivationSink`) and stops
its rebroadcast ticker, so peers that have not yet collected all six
acknowledgements cannot converge on the same group key within the same epoch.
The next epoch derives a fresh session and a fresh key, producing a group-key
split across the network.

The convergence mechanism has two halves:

1. **Gossip (committing node).** After `ActivateCandidate` succeeds, the
   committing node encodes the assembled certificate
   (`encodeThresholdActivationCertificate`, magic `QTD3ACT1`, version 1) and
   broadcasts it as `MsgTypeTDilithium3DKGActivationCertificate` (type 101) in a
   bounded burst (3 rounds, 2 s spacing). The certificate is self-verifying: it
   carries all six signed acknowledgements bound to the session digest and
   transcript.

2. **Adoption (receiving node).** A node that receives a type-101 packet in
   `handleTSSMessage` calls `adoptTDilithium3DKGActivationCertificate`, which
   decodes the certificate, extracts the activation epoch from
   `Acknowledgements[0].ActivationEpoch`, and reconstructs the session and
   identity verifier. When a ceremony is live for the same epoch, the live
   inbox's `verifyIdentity` is reused; otherwise the session and verifier are
   derived from the activation epoch (deterministic per D1–D8, so both paths
   yield the same digest). `ActivateCandidate` is then called with the locally
   derived `sessionDigest`, which re-checks the epoch/session guard and runs
   `VerifyCandidate` against the local candidate share — fail-closed on any
   mismatch. On success the finality surface is registered via
   `registerTDilithium3SigningFinalitySigner`, mirroring the ceremony's
   post-finalize path.

Adoption is idempotent: a node that already committed the same certificate
through its own exchange short-circuits in `ActivateCandidate` (stored-certificate
byte-compare), so gossip retransmissions and self-reception are harmless.

## 7. Verification Plan

Required for every non-trivial change (R40.D):

```powershell
go build ./...
go vet ./node/...
gofmt -l <touched files>
go test -timeout 180s ./node/ ./wallet/tss/protocol/dilithium3v1/
```

New tests, all in `node/`:

1. **Session derivation determinism** — two independently built nodes with the
   same chain state and roster produce the same session digest; changing the
   activation epoch, the key generation, the chain id, or any roster entry
   produces a different digest.
2. **Roster epoch rule (D1)** — a session for activation epoch `N` reads the
   `N-1` roster; a missing, at-bootstrap, or non-finalized-but-uncaptured
   roster fails closed; a six-entry roster is accepted.
3. **Committee rule (D2)** — committee is `[1..6]` in roster order; a local
   address at roster position `i` yields recipient position `i`; a roster of a
   size other than six is refused.
4. **Identity key agreement (D6)** — the roster public key for the local address
   equals `blockProducer.ValidatorKey().Public()` bytes.
5. **Gates closed (D9)** — with either gate unset, `RunDistributedDKG` returns
   the legacy group key and `runTDilithium3DKGCeremony` is never entered.
6. **No fallback (D8)** — with gates open and a peer removed, the ceremony
   returns an error and no legacy key is returned. This is the regression guard
   for the silent-substitution case.
7. **Six-node P2P end-to-end** — reuse the `tdilithium3_dkg_group_p2p_test.go`
   harness to drive the ceremony through the production entry point, and assert
   all six nodes derive the same 1952-byte public key and transcript digest.
8. **Crash resume** — kill a node mid-ceremony, restart it, and confirm it
   rejoins the same session digest from its journal.
9. **Inbound authorization preserved (D7/D9)** — the accept path must not become
   a bare inbox-nil check. With either gate unset, with mainnet, or with a chain
   mismatch, `handleTSSMessage` drops a correctly signed v1 packet instead of
   delivering it.
10. **Activation ownership (D8)** — with gates open, the epoch transition must
    not activate the chamber with the legacy group key; the chamber stays in
    `ExecutiveDKGRunning` until the ceremony's `setDKGCompleteForEpoch` activates
    it. Guarded by item 5's gate-closed case in unit tests, and observed on the
    devnet run below.

Coverage status:

| Item | Test |
|---|---|
| 1 | `TestTDilithium3DKGSessionDerivationIsDeterministicAndChainBound` |
| 2 | same test (roster epoch, bootstrap boundary, uncaptured epoch) plus `TestTDilithium3DKGEpochRoster…` |
| 3 | `TestTDilithium3DKGCommitteeFollowsRosterOrder` |
| 4 | `TestTDilithium3DKGIdentityKeyMustMatchRosterEntry` |
| 5, 6 | `TestNodeConsensusDKGRunnerSelectsV1BackendWithoutFallback` |
| 7 | `TestTDilithium3DKGCeremonyP2PCrossProcess` (six processes, real `p2p.Host`, production entry point) |
| 8 | `TestTDilithium3DKGCrashRecoveryAtEveryBoundary` plus the resume assertion inside the cross-process test |
| 9 | `TestTDilithium3DKGInboxRejectsUntrustedAndReplayedMessages` |
| 10 | six-process devnet run (below); gate-closed half in item 5's test |

Six-process devnet result (networkId 1333, both gates open, `tssDistributedDKG`
true, fresh chain data and a fresh genesis timestamp so wall-clock epoch 0
matches the chain head):

- Epoch 0 and 1 boundaries log `Executive chamber members selected for epoch N:
  1 members (DKG pending - group public key not available, will retry)`, which
  is the withheld-key path; the chamber enters the ceremony in `DKGRunning`.
- Epoch 1 and 2 fail closed by design, which shows the session rule is reached
  and enforced: epoch 1 has no lower boundary to anchor on (D1), and epoch 2's
  roster epoch is the bootstrap boundary.
- Epoch 3 completes on all six nodes with cross-process agreement: one distinct
  session (`1e8773055d178b04`), one distinct transcript (`27af23c857b46a3d`),
  one distinct group key (`2b748707bf404953`), and six
  `GOV- executive chamber activated for epoch 3 via distributed DKG
  (threshold=1, participants=1, groupPubKey=…)` log lines with no legacy
  variant.

The chain stayed healthy throughout (slots advancing, no DKG errors). The
run is a liveness and agreement check, not a substitute for the unit and
six-process harness tests above, and not a cryptographic review.

### Bootstrap rule revision (R74)

The first devnet run pinned the `epoch <= bootstrap` fail-closed rule in
`lookup`/`lookupCaptured` (`node/tdilithium3_dkg_epoch_roster.go`): the
boundary the node captured first is the bootstrap boundary and is **never
servable**, so activation epoch 2 (roster epoch = bootstrap) failed closed and
the first usable activation was epoch 3.

Re-examination against the real production scenario: a node that captures the
roster while **applying its own blocks** (the normal genesis-start case, and
any live node that has not yet bootstrapped-synced) saw the whole boundary, not
a partial sync. The partial-processing hazard the original rule guarded
against applies only to a node that **joined the chain during a bootstrap
sync**, in which case epochs at or below its first captured boundary may
indeed have been observed mid-processing. The rule as written conflated the two.

The revision: `lookup`/`lookupCaptured` now refuse only `epoch < bootstrap`,
making the bootstrap boundary epoch itself servable. The five pinned unit
tests in `node/tdilithium3_dkg_epoch_roster_test.go` and
`node/tdilithium3_dkg_ceremony_test.go` were updated to the new boundary
condition. The safety invariant — a node that joined after the boundary and
never observed it remains refused — is unchanged: `bootstrapSet` is false
until the first capture, so a joiner still fails closed until it has captured
its own boundary.

With this revision, on a fresh devnet chain the first usable activation
moves from epoch 3 to **epoch 2** (roster epoch 1 = the bootstrap boundary,
now servable). Epochs 0 and 1 remain permanently fail-closed by `tdilithium3DKGSessionRosterEpoch`,
which refuses activation epochs below 2.

### Mainnet activation gate (R75)

The original design permanently excluded mainnet from the v1 path. R75 turns
that exclusion into a **double gate**: the v1 ceremony, both inboxes, the seal
executor, and the reshare hook now consult
`experimentalTDilithium3V1EnabledForNetwork(networkID)`
(`node/threshold_backend_selection.go`), which requires
`QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1=1` everywhere and additionally
`QAU_ENABLE_TDILITHIUM3_V1_MAINNET=1` on chain id 1668. Non-mainnet behaviour
is unchanged. The `config.Validate` guard that refused
`tssDistributedDKG: true` on mainnet is keyed to the same acknowledgement,
because the v1 ceremony reaches the runner through the block producer's
distributed-DKG path; the separate startup guard that refuses mainnet
**legacy** runtime DKG without imported key-share files is untouched — v1
configurations run with `tssTotalShares=1` (single legacy signer) and the v1
ceremony owns the executive chamber's threshold key. Pinned by
`TestExperimentalTDilithium3V1EnabledForNetworkDoubleGate`.

## 8. Required Documentation Updates (on approval)

Applied:

- `2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`: the "Restarting uses a new
  session identifier and new contributions" sentence was replaced with the D3
  wording, and a "Session Derivation and Wiring" subsection was added under
  Round 0 pointing at this document.
- `2026-09-24-qau-dilithium3-v1-cnf-rss-dkg.md`: Task 9 and its acceptance items
  were appended, and the phase acceptance boundary now includes reachability of
  the ceremony from the running node.

## 9. Open Items Requiring Explicit Approval

1. **Consensus accessor for the epoch committee** (D1/D2 alternative). Would
   make the roster epoch and the committee finality-anchored and consensus-
   derived, and would lift the "exactly six active validators" restriction. It
   is the only change in this document's orbit that touches `consensus/`, so it
   is not proposed for this round.
2. **Consensus-backed key generation counter** (D4 follow-up). Needed before
   reshare, not before the initial ceremony.
3. Unchanged and still open from the CNF-RSS design: online threshold signing,
   same-key reshare, leader replacement.
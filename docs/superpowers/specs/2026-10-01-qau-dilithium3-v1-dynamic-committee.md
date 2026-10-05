# QAU Dilithium3 v1 Dynamic Committee (R76) — Design

**Status:** R76a + R76b implemented and devnet-validated (r76net7v3: the
seven-validator chain derived the C=7 committee, ran three C=7 ceremonies per
node, and all seven members adopted the active share; see "R76b devnet
acceptance" below). The signing MPC carries pinned rows for C = 6 and C = 7
and fails closed elsewhere — see the
"R76b status notes"). Devnet acceptance (test-plan items 4-5) and R77 are the
remaining work.
**Date:** 2026-10-01
**Follows:** `2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`,
`2026-09-26-qau-dilithium3-v1-dkg-session-derivation.md` (section 9, open
item 1), `2026-09-27-qau-dilithium3-v1-signing-executor.md`
**Successors:** reshare / committee rotation (R77, separate spec)

## Purpose

The v1 threshold-Dilithium3 executive-seal path currently requires the epoch
roster to contain **exactly six** entries; every other size fails closed
(`node/tdilithium3_dkg_session_derivation.go`, D2 of the session-derivation
spec). That restriction matches today's six-validator mainnet but forbids
onboarding a seventh validator — and therefore forbids an open validator set
altogether — with v1 enabled.

R76 makes the v1 committee **consensus-derived and dynamic**: the committee is
a deterministic, finality-anchored function of the epoch's validator roster,
sized C ∈ [6, C_max=12] with threshold t = ⌈2C/3⌉, so any validator-set size
n ≥ 6 has one canonical committee. Nothing else changes at C=6: today's
mainnet (n=6) derives the same committee, threshold, and session inputs as
before, bit-for-bit.

R77 (not this document) adds same-key reshare so a committee whose membership
changed can hand the shares to its successor without a new key.

## Non-Goals

- Committee sizes above 12. The CNF-RSS cost grows as C(C, ⌈C/3⌉); beyond ~15
  it stops being a parameter choice and becomes a different DKG family. A
  committee cap of 12 is the largest size this line can carry without new
  cryptography, and it already covers a 10,000-validator chain via rotation.
- Validator-set growth limits, staking economics, slashing. Those are
  consensus-layer properties that already exist (unbounded staking, validator
  queue, `epochsPerValidatorRotation`); R76 only consumes them.
- Reshare, online signing beyond sealing, leader-replacement fairness. Those
  stay on the §9 open-items list; R77 handles the first one.

## D1 — Committee definition **APPROVAL REQUIRED**

For activation epoch E with finalized roster epoch RE = E−1 (unchanged from
the R74 bootstrap rule), let `R` be the ordered epoch roster (already
finality-anchored, canonical ascending-address order, size n).

```text
C = min(n, 7)                  // committee size caps at the largest pinned row
t = ceil(2*C/3)                // signing threshold; t(6)=4, t(7)=5
committee = (n <= 7) ? R
         : stakeWeightedSample(R, seed = VRFAccumulator(RE-2), C = 7)
```

Consequences, all deliberate:

- **n ≤ 7 (every chain today):** the committee is the whole roster. No
  sampling randomness enters the derivation; a chain with six validators keeps
  producing exactly the committee it produces now, so nothing observable
  changes at activation epochs ≥ 2.
- **n > 7:** the committee is the fixed-size 7-member epoch sample of the
  roster. The sampling rule reuses the proven `SelectExecutiveForEpoch`
  construction: sequential proportional-without-replacement selection seeded
  by the epoch's VRF accumulator (`consensus/provinces.go`, R88-F cold-start
  semantics included). Same roster plus same accumulator ⇒ same committee on
  every node; no consensus message and no new block data is introduced.
- n < 6 fails closed (`consensus.MinValidatorsForChambers` already enforces
  this boundary for activation; the v1 gate keeps its own check).

Revision note (2026-10-05): this D1 formula originally clamped to 12 because
the DKG family range is [6, 12]. The signing-MPC reality measured by R76b is
narrower — only C=6 and C=7 have operational parameter rows (C=8 needs ≈265
parallel slots / ~2 MB per party per request; C ≥ 9 is provably degenerate
under the mode3 fixed hint channel) — so the committee family stays at the
pinning boundary and oversize rosters sample at C=7 instead of stalling past
12. The sampling inputs (per-entry stake and the VRF accumulator of RE-2,
both recorded in the v2 epoch-roster sidecar) are committed into that record's
digest so a tampered weight or seed fails closed on load.

Rejected alternative: committee size from a config value. A config knob splits
the committee across operators who set it differently; a pure function of the
finalized roster cannot disagree.

Rejected alternative: fixed C = 6 with sampling whenever n > 6. That rotates
the committee under mainnet today's size-6 set as soon as a seventh validator
appears and changes committee membership — and hence the DKG roster digest —
even when every existing member is retained. Keeping the committee identical
to the roster while n ≤ 12 removes that discontinuity.

## D2 — Threshold rule **APPROVAL REQUIRED**

`t = ceil(2C/3)`:

| C | t | max offline | max corrupt |
|---|---|-------------|-------------|
| 6 | 4 | 2 | 3 (CNF: coalitions < t miss a group) |
| 7 | 5 | 2 | 4 |
| 9 | 6 | 3 | 5 |
| 12 | 8 | 4 | 7 |

This preserves the 4-of-6 geometry bit-for-bit at C=6 and keeps the CNF
group size N−t+1 = ⌊C/3⌋+1 (3 for C ∈ {6,7,8}, 4 for C ∈ {9..12}), so the
existing per-participant storage growth stays sub-quadratic in C
(group counts 20 → 35 → 56 → 126 → 210 → 330 → 792 for C = 6..12).

## D3 — Protocol parameterization **APPROVAL REQUIRED**

The Dilithium3 v1 profile stops being a singleton:

- `Parameters` keeps {Participants, Threshold} and `Validate()` accepts the
  family {(C, ⌈2C/3⌉) : 6 ≤ C ≤ 12} instead of one tuple
  (`wallet/tss/protocol/dilithium3v1/params.go`).
- `RSSGroupMask` widens from `uint8` to `uint16`; `rssPositionMask =
  (1<<C)-1` computed from the session's C; canonical group enumeration,
  `GroupsForPosition`, and validation all take C as input
  (`rss_topology.go`). Group masks stay bit-sets of committee positions; the
  wire format declares the mask width from C (1 byte for C ≤ 8, 2 bytes
  below).
- `share_encoding.go`'s `participantCount != 6` check and every other
  numeric-6 assumption enumerate to the session committee length. All
  per-session objects already carry the committee; no bare global remains.

Wire compatibility: all session objects embed `CommitteeID{Version:1,
Threshold:t, Participants:…}`, and every envelope digest includes the
committee digest, so a mixed-C network cannot accidentally talk across the
line. Transcripts from a C=6 session are rejected by a C=7 session by
digesting, not by version parsing.

## D4 — Derivation location **APPROVAL REQUIRED**

Revised from the session-derivation spec's open item 1: **no `consensus/`
change is needed**. The epoch-roster store is already finality-anchored and
per-epoch; it is extended to also capture each entry's stake weight and the
boundary VRF accumulator (both already present in the block-processing path
at capture time — stake from the validator set being captured, accumulator
from `qpos.GetEpochVRFAccumulator(epoch-2)`, the same source the R88-F
executive selection uses). Committee selection is then a pure, replayable
function of one persisted record:

```text
committee(roster) = (n <= C_max) ? all positions 0..n-1
                  : stakeWeightedSample(roster entries, seed = recorded
                    VRFAccumulator, target C_max)
```

A record captured by a pre-R76 binary carries no stake/accumulator fields;
sampling against it fails closed (committee = full roster whenever n ≤ 12,
which covers every such record in practice), and n > 12 without weights
refuses instead of guessing. Cold-start without a recorded accumulator fails
closed for n > 12 the same way R88-F does.

Rejected (again): reading the live `ValidatorSet` at derivation time — that
is precisely the mutable, epoch-untagged state the roster store exists to
replace.

## D5 — Session derivation update **APPROVAL REQUIRED**

D2 of the session-derivation spec (committee = roster, exactly six) is
superseded as follows, everything else unchanged:

- `tdilithium3DKGCommitteeForRoster` asks the accessor for (members, C, t),
  validates C ∈ [6,12] and t = ⌈2C/3⌉, validates every member against the
  roster snapshot, profiles as `DefaultProfile(C)`.
- Session nonce derivation is unchanged textually; the committee digest
  already binds C, so session IDs change with the committee automatically.
- Participant IDs stay `position+1`, positions now over C instead of 6.
- The make-no-progress rule is unchanged: absent accessor data ⇒ no session
  ⇒ fail closed; no fallback to the legacy backend anywhere.

## D7 — Phasing **APPROVAL REQUIRED**

R76 ships in two slices because the signing MPC's security parameters are
derived from the CNF group count, so every new C is a cryptographic
re-derivation, and because sampling machinery is dead code until a chain
actually has more than C_max validators:

- **R76a (this round):** N ∈ [6, 12], committee = the whole epoch roster
  (no sampling, no consensus change, no cold-start questions), threshold
  t = ⌈2N/3⌉, CNF topology/parameters/encodings parameterized, signing
  rejection parameters re-derived per C from the formulas in the
  signing-mpc spec. At n > 12 every ceremony fails closed with an explicit
  "validator set exceeds the v1 committee family" error.
- **R76b (later, before any chain exceeds 12 validators):** the
  stake-weighted sampling accessor of D1/D4, capping the committee at 12
  while the validator set grows unboundedly.

**Update (2026-10-05): the D1 sampling accessor is landed.** With the
measured signing-family boundary at {6, 7} (see the revision note in D1), the
accessor samples the 7-member committee the moment the roster exceeds 7 —
`node/tdilithium3_dkg_committee_sampling.go`: sequential proportional-without-
replacement draws keyed sha3(domain ‖ roster epoch ‖ captured VRF accumulator
of epoch−2 ‖ round) over remaining stake, canonical ascending roster order for
the output. The epoch-roster sidecar went to format v2 (per-entry stake +
captured seed, both folded into the record digest; pre-accessor records and
records with no recorded seed refuse to sample instead of guessing). All
committee-vs-roster pairing now goes through the sampled selection
(`tdilithium3DKGRosterBindings` and `tdilithium3DKGCommitteeForRoster` agree
on it byte for byte), so two nodes at the same head derive the identical
committee for any n. Unit coverage: `TestTDilithium3DKGCommitteeSelection`
pins whole-roster identity inside {6, 7}, determinism over 8 distinct seeds,
stake-proportionality of the weighted draws, and fail-closed behavior on
missing stakes/seeds. A live-chain exercise of an n > 7 validator set remains
the optional follow-up at devnet scale (no current chain reaches n = 8).

R76a alone removes the "exactly six" restriction for every realistically
sized network today and for every chain up to 12 validators permanently.

## D6 — Compatibility and rollout **APPROVAL REQUIRED**

- A chain at n ≤ 12 with the R76 binary derives the identical committee,
  threshold and session digest as the R75 binary. **No flag-day, no
  re-ceremony, mainnet adoption is a drop-in binary upgrade.**
- The first epoch where n crosses 12 (or changes within >12) changes the
  committee digest, hence the session digest, hence the DKG output: the
  chamber re-keys by running the ceremony again. That is the intended
  property — R76 is "committee change ⇒ new key via ceremony"; R77 removes
  the re-key cost for the stable-key case.
- Fail-closed everywhere on uncertainty: missing accumulator, missing
  boundary roster, C out of range, t mismatch, member not in the roster —
  all refuse.

## Test Strategy

1. **Pure-function pinning (consensus):** same roster+accumulator ⇒ same
   committee across 100 resamples; n ∈ {5,6,7,12,13,100,10000} gives the
   D1 shape; cold-start paths refuse exactly where R88-F refuses.
2. **CNF topology per C:** group count = C(C, ⌊C/3⌋+1); every participant
   holds C(C−1, ⌊C/3⌋) components; every t-subset intersects every group;
   every (t−1)-coalition misses some group; leader rotation exhausts
   exactly the group.
3. **Cross-C wire rejection:** a session digest from C=6 fails against
   C=7 bindings and vice versa.
4. **Six-node devnet regression (unchanged):** epoch-2 ceremony identical to
   R74's (same digest, one certificate) — proves D6's no-op claim.
5. **Seven-node devnet (new acceptance):** start 6, then admit a 7th
   validator at epoch E; the ceremony at E+2 runs with C=7, t=5,
   C(7,4)=35 groups, one group key, activation gossip converges, QTD
   finality keeps advancing. This is the end-to-end proof of the open
   validator set.

## Acceptance Boundary

R76 is complete when: items 1–3 pass; item 4 reproduces the R74 devnet run
bit-for-bit; item 5 passes; `go build ./...`, `go vet`, full
node/p2p/consensus/wallet suites green; the session-derivation spec's D2
paragraph is amended and §9 open item 1 removed.

## Open Items Left Untouched (unchanged from the originals)

- Same-key reshare when the committee membership changed but the key must
  persist (R77).
- Consensus-backed key-generation counter (still epoch-derived, D4 of the
  session-derivation spec stands).
- Committee sizes > 12 / non-CNF families.

## R76a status notes (2026-10-01, implementation landed)

Land: full DKG/committee family for C in [6, 12] (t = ceil(2C/3), group size
floor(C/3)+1) — topology and mask types widened to uint16 with 2-byte wire
encoding, every session/roster/share/journal/encoding surface parameterized.

Notable consequences:

1. **Wire format changed.** Group masks serialize as two bytes big-endian
   everywhere (group seed messages, acknowledgements, complaints, public
   contributions, share encodings, sampler seeds). All committee members must
   upgrade together; the R74-era devnet form is NOT cross-compatible with the
   R76a binary (mask position in digests differs). v1 remains
   double-gated/experimental, so no production traffic is affected.
2. **The signing MPC stays pinned to the four-of-six parameter row.**
   Sessions with C != 6 DKG and activate normally; signing requests fail
   closed at the request boundary (profile validation) and again at the
   attempt boundary (`ErrUnsupportedSigningCommitteeSize`). Signing for
   C = 7..12 requires re-deriving B, r, r-prime, J per size (the hint-check
   probability needs a per-size Monte Carlo estimation like the pinned C = 6
   row's 0.6506/40k-samples value) — that is R76b.
3. **Acceptance boundary deferred to R76b.** Items 1-3 of the test plan are
   covered by unit/property tests; items 4-5 (devnet runs) run after R76b
   lands, since seven-node sealing is the point of the exercise.
4. Allocation rule: C=6 keeps the legacy bit-exact assignment
   (TestRSSFourOfSixAllocation pins it); C>=7 uses intersection load
   balancing (ascending intersection size, least-loaded member wins).

## R76b — signing-MPC parameter family (derived 2026-10-01)

The R57 hyperball parameter procedure was re-run per committee size with the
family-owned component count `owned(C) = ceil(binomial(C, g)/t)` in the shift
bound `B = 1.3 * sqrt((K + L/nu^2) * N * owned) * sigma * sqrt(tau)` and the
divergence `M = 2^(expo/t)` (constant per-slot acceptance 2^-expo). The
derivation code is `.local-only/scripts/r76b_hyperball_family.go` (a flagged
generalization of the reviewed R57 `r57_hyperball_params.go`; local analysis
only, never a production path). For every candidate row the public combine
checks were Monte-Carlo-estimated on the accepted-randomness model and the
sanity baseline reproduced the pinned C=6 row (measured Phint 0.6515 vs the
pinned 0.6506 at matching resolution; J = 11).

Findings:

| C | t | g | groups | owned | expo | 1/M per-party | Phint | J | wire/request/party |
|---|---|---|--------|-------|------|---------------|-------|---|--------------------|
| 6 | 4 | 3 | 20 | 5 | 3.30 | 0.5645 | 0.6515 | 11 | 83.8 KB |
| 7 | 5 | 3 | 35 | 7 | 4.95 | ~0.51 | ~0.50 | 43 | ~328 KB |
| 8 | 6 | 3 | 56 | 10 | ~7.2 | ~0.43 | ~0.39 | ~265 | ~2.0 MB |
| >=9 | >=6 | >=4 | >=126 | >=21 | none | - | ~0 | - | - |

Decision: R76b pins only C=6 (unchanged R57 row) and C=7 (new row at
expo = 4.95; refined numbers pinned in `params.go`). C = 8 is documented
data, not a supported row: a 254+ parallel-slot request (~2 MB per party) is
an operational non-starter. C >= 9 is provably degenerate under this
construction — the hint-weight check collapses because the per-coefficient
randomness spread scales with sqrt(owned) while the HighBits segment width
of mode3 is fixed. The committee range [6, 12] stays for DKG/activation
(R76a), but the signing gate keeps failing closed outside the pinned rows:
today that is exactly C = 6 and C = 7. Chain-level validator sets above 7
therefore need the committee sampling accessor (D1, consensus-side) — that
scope is unchanged and stays an open item.

## R76b status notes (2026-10-02, implementation landed)

The pinned C=7 row (40k Monte Carlo, measured per-key Phint spread
[0.466, 0.567] over 40 keys x 2000 samples): expo = 4.95, M = 1.9862,
B = 779.31, r = 402748.8, r-prime = 402847.0, P1 = 0.9996, P2 = 1.0000,
Phint = 0.5052, per-slot acceptance 0.5045, J = 43 (~328 KB of wire per
request per party).

The signing MPC is now parameterized by a pinned-row table
(`SigningParametersForParticipants`, failing closed with
`ErrNoSigningRow`/`ErrUnsupportedSigningCommitteeSize` outside {6, 7}): the
signing attempt, the executor gate/session/schedule/party, and the node-side
binding, envelope, schedule, and seal surfaces all derive their per-signer
counts, masks, and slot budgets from the row instead of the four-of-six
constants; `SigningMaxParallelSlots` (43) bounds the transport. The session
identifier requires the signer count to equal the committee's threshold, so
a five-signer subset is valid only on a seven-member committee.

Coverage: the R76a fail-closed test now pins C = 8..12 rejection at the
attempt boundary with the row table as second line of defense; new R76b
tests run the C=7 row end to end on the generalized RSS family — reference
driver, in-process executor session, and exported party surface agree byte
for byte, and the request schedule stays within the row's 43-slot budget.
Remaining R76b scope: the devnet seven-validator seal run (test-plan items
4-5) and the R77 reshare/rotation work.
## R76b devnet acceptance (2026-10-02, r76net7v3)

A seven-node devnet (fresh 7-validator genesis, DEVNET ONLY keys, chain 1333)
exercised the full R76 family lifecycle live: every node derived the same
C=7 session digest with distinct positions 0-6, completed three DKG
ceremonies, and all seven validators adopted the C=7/t=5 active share via the
activation exchange or its gossip certificate. The run surfaced and the
follow-up commit `7a3f6b0` fixed four residual six-member constants (group
seed delivery range, transport recipient bound, ceremony group enumeration,
acknowledgement dedup width) plus the finality seal-quorum threshold; the new
seven-node in-process network test reproduces the two failure modes offline.
Devnet evidence is captured in the harness run; a known, pre-existing
consensus-layer gap (the QTD executive-chamber voter set and the proposer
announcement derive from different schedules while the chamber is a one-member
DKG-pending committee) keeps the five-of-seven seal from exercising the live
finality path before R77 rewires the chamber to the v1 committee.


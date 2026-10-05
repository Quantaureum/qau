# QAU Dilithium3 v1 Same-Key Reshare and Committee Rotation (R77) — Design

**Status:** Draft design. Follows from the R76 dynamic-committee spec's D4
deferred item: membership change without a key change.
**Date:** 2026-10-02
**Follows:** `2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`,
`2026-10-01-qau-dilithium3-v1-dynamic-committee.md`
**Goal (per programme brief):** validators can freely join and leave the set;
the executive-chamber threshold committee rotates from the (unbounded) set
while the v1 group key survives the rotation. Deliverables of this design's
implementation track: code + tests + a devnet run that observes a committee
change (add and remove) with the group public key unchanged.

## 1. Why same-key resharing

R76 made the committee itself dynamic, but committee change today triggers a
fresh DKG — a new group key per roster epoch. That is acceptable for a
mainnet boot chain where the chamber identity rotates anyway, yet it has two
hard limits the R77 programme item addresses directly:

1. **Validator churn breaks pending-seal continuity.** Seals anchored on the
   epoch key cannot be produced by the new committee for in-flight slots
   unless the outstanding seals are re-cut, and the finality engine cannot
   see a smooth chain of identical group keys across the boundary.
2. **Trust windows.** A fresh DKG re-bootstraps the whole secret at every
   roster change, even when the rotation is a single adjacency (one joiner
   or one leaver). A same-key reshare turns a one-step rotation into a
   delta protocol that never re-randomizes the secret.

## 2. The algebraic picture and the constraint

The v1 key (see the CNF-RSS design, section 3) is a componentwise sum across
the family's canonical groups:

    T = sum_G t_G   with   t_G = A*s1_G + s2_G  (mod q)

where the sum runs over all canonical groups `G ⊆ [C]` of size
`g = floor(C/3)+1` (there are `binom(C, g)` groups), and the secret
components `(s1_G, s2_G)` are derived from the group seed — a value every
group member holds equally. A reshare must preserve

    sum_{G' in NewGroups} t'_{G'}  =  sum_{G in OldGroups} t_G

in both coordinates, because the new committee's assembled mode3 key is
`sum t'_{G'}` and the target is `T`. Every construction step must keep the
*access structure* intact: any coalition of fewer than the new threshold
`t' = ceil(2C'/3)` members must continue to miss at least one group's
contribution.

**Necessary condition (carry invariance).** A group that loses every member
can no longer supply its component; if the rotation removes a set `R` of
members and any old group is contained in `R`, the old key is not
reproducible and the ceremony must fall back to fresh-key DKG (R76
semantics). Rotation is therefore defined only when the new committee keeps
at least one member of every old group. With group width `g = 3` this
invariant holds exactly when the membership delta touches fewer than `g`
positions: single-join, single-leave, and one-in/one-out swaps all qualify.

## 3. Rotation shapes

The family committees are small (6 <= C <= 12); only three shapes are
considered. The devnet acceptance drive demonstrates the first two.

**Add (C -> C+1).** Every old group carries, since all its members remain.
The new groups — those containing the joiner `n` — appear, `binom(C, g-1)`
many, and must contribute zero in aggregate. The joiner participates in all
of them, so it acts as the *weaver*: it collects the freshly derived
components of the first `binom(C, g-1) - 1` new groups and computes the
correction `r* = -sum r_j` for the last one, whose other members it
instructs to adopt the adjusted component. Because the public contribution
of the last group is pinned by the publicly computable relation
`t'_last = -sum_{j != last} t_j`, the adjustment is verifiable from public
data, and the only value that moves is an aggregate the weaver itself
already knew — knowledge of a sum does not grant coverage of any individual
new group, so no coalition's access profile widens.

**Remove (C -> C-1).** The leaver `x` is dropped. Old groups not containing
`x` carry. Old groups `{x, a, b}` containing `x` retain at least two
continuing members; their component is *folded* into the residual group
`{a, b, m(a, b)}`, whose third member `m(a, b)` is chosen by a canonical
rule inside the continuing set (for example the smallest remaining index
outside `{a, b}`). The target group's effective component becomes
`c_{a,b,m} + c_{x,a,b}`. The fold is anchored by a continuing member of both
groups (which legitimately holds both components) and delivered to the
target's third member over the existing authenticated private channel.
Security check: a coalition `T` of `t'-1` new members still misses the old
group disjoint from `T`; folded values travel only inside their target
group's envelope, and every fold source shares at least two members with
its target, so no coalition gains coverage it did not already have.

**Swap (one leaves, one joins).** Compose: remove `x` (fold), then add `n`
(weave). Folded and woven deltas interact only through the canonical
selector `m(., .)`; the access-structure argument is preserved because
folding targets only surviving old groups and weaving only joiner groups.

## 4. Wire protocol (delta over the R76 ceremony path)

R77 reuses the R76 machinery end to end; one new message type is needed:

1. **Session derivation.** Anchored on the epoch `e-1` roster (as in R76),
   but the reshare session carries both the previous and the new committee
   descriptors, and binds the previous group public key. Session digests mix
   both committee encodings, so a certificate from a wrong-shape ceremony
   verifies nowhere.
2. **Group component establishment.** New groups (weave groups on adds,
   fold targets on removes) run the regular per-group seed/verify dance with
   the reshare session digest. Carry groups skip the seed phase: their
   components move unchanged, re-encrypted under the new committee roster.
3. **Delta redistribution (`ReshareDelta`).** One new wire message delivers
   the per-group adjustment (the fold source component for fold targets,
   the weaver correction for the designated last new group), signed by the
   delta authority (fold anchor or weaver) for the reshare session digest.
   Recipients recompute the resulting group public contribution and check
   the publicly derivable relation from the previous active certificate
   before accepting; the assembly completes only when the whole-family
   relation `sum t'_G == T` holds.
4. **Activation.** The existing activation-certificate collection — one
   acknowledgement per new-committee member — promotes the reshared share
   for epoch `e`. Outgoing members certify their own retirement by absence.

An adversarial member that equivocates on a delta is indistinguishable from
a stall: the fallback is fresh-key DKG at `e+1`, exactly the R76 behaviour,
so rotation never degrades liveness below the R76 baseline.

## 5. Committee sampling from an unbounded validator set

The validator set itself is unbounded; the v1 family committee stays in
`[6, 12]`. The deterministic function from the finalized epoch roster to the
committee is member-order preserving: when the roster grows past `C_max`,
the committee takes the first `C` members by the roster's own ordering, and
the DKG/reshare pair is carried out against that set. This keeps the
executive-chamber identity stable across ordinary churn (most membership
changes do not touch the first twelve finality-weighted validators), matches
the signing-pinned rows kept in R76b (`C in {6, 7}`), and keeps the
per-committee signing parameter table the only row-derivation point. A
committee at `C = 8..12` that cannot sign (no pinned row) stays an
outstanding gating item for a later signing-parameter row.

## 5a. Norm carrying: fold multiplicity in the signing bound

Resharing folds reclaim the norm budget: a folded component is the mod-q sum
of `mult` fresh base contributions, and the signing protocol's per-signer
partial-norm check must scale its bound by exactly the multiplicity sum over
the groups allocated to a signer. The reference reconstruction
(`reconstructPartialSecrets`) and the executor party bound
(`SigningExecutorParty`) both consume `RSSComponent.Multiplicity`; freshly
dealt components carry `1`; `addRSSComponent`/`subRSSComponent` accumulate.
The value is a deterministic function of the rotation lineage
(committee versions), is byte-identical across honest members, is part of
the persisted share encoding (share version 3; version-2 shares decode with
multiplicity 1), and discloses nothing the rotation plan does not already
publish. This closed a genuine production-readiness defect the first
choreography seam (`TestTDilithium3ReshareRemoveSeamSignsUnderSameKey`)
surfaced: rotated shares otherwise violated the zero-leakage coefficient
bound `owned * RSSComponentEta` during an honest signature and the attempt
aborted.

## 6. Acceptance plan

- **Unit / family tests:** `C=6 -> C=7` single-add reshares preserve the
  public key; `C=7 -> C=6` single-remove reshares preserve the public key;
  swaps compose the two; an adversarial delta from a non-authority member
  aborts closed; the fresh-key fallback engages on multi-position
  membership deltas. The R76a ceremony tests stay as regression.
- **In-process remove seam (2026-10-03, landed):**
  `node/tdilithium3_reshare_seam_test.go` runs the real seven-node DKG
  ceremony, rotates to six via the remove runner, and signs with a fresh
  four-of-six quorum whose signature verifies natively under the never-
  rotated group public key. This is the protocol-level acceptance for the
  remove shape; the add-shape seam (weave-group rounds + weaver correction
  delivery) lands with the wire-level ceremony in the same pass as the
  devnet run below, against the same harness family.
- **In-process add seam (2026-10-04, assembly landed / signing gated):**
  `node/tdilithium3_reshare_add_seam_test.go` runs the complete six-node
  ceremony, drives the weaver's twenty joiner-group rounds for the seven-
  member committee, applies the correction, assembles seven validating
  shares, and asserts key invariance
  (`TestTDilithium3ReshareAddAssemblesSameKeyShares`). The five-of-seven
  signing acceptance (`TestTDilithium3ReshareAddSeamSignsUnderSameKey`)
  is one flag away (`QAU_ENABLE_R77C_SIGNING_ROW=1`) and is gated pending
  R77c: the add-shape correction concentrates the joiner-group zero-sum
  into one component with multiplicity 14 in the shipped plan (14
  non-correction weave groups), so the pinning of the R57 HRej radius
  (`eta=1`, C(6,3)=20 fresh groups) would have needed a rotated row the
  envelope measured out — see section 7. Remove-shape signing needed its
  own row after all (the acceptance radius margin is sized for eta=1
  material and folded secrets exhaust it deterministically): it now has
  one — the R77d rotated C=6 row, see section 7.
- **Wire + ceremony driver (landed 2026-10-04, remove shape):**
  `MsgTypeTDilithium3ReshareDelta` (102) carries the versioned threshold
  envelope around `dilithium3v1.ReshareDeltaWire` (kind fold/correction,
  NEW-committee anchor/recipient coordinates, full component including its
  fold multiplicity). The p2p payload validator, the session-structure
  checker (sender must be the new-coords anchor, recipient must be the
  private addressee), the authenticated inbox replay key and the runner
  registry accept it end to end
  (`node/tdilithium3_reshare_ceremony_test.go` drives a real 7nodeD K G
  through the full stack into the six-member rotation, asserting byte-level
  cross-member agreement on the carried partitions). Production entry:
  `tryTDilithium3ReshareRemoveRotation` inside `runTDilithium3DKGCeremony`
  intercepts the epoch whose roster committee is exactly the active share's
  committee minus one member; the rotation runs against the reshare-shaped
  session (previous-committee && previous-key bound nonce), stores the
  rotated candidate on the SAME generation, and runs the usual
  acknowledgement activation exchange before the finality surface
  re-registers. Growth and multi-position churn still fail closed to the
  fresh-key ceremony.
- **Devnet acceptance (`r77net*`, PASSED 2026-10-04):**
  six-genesis-validator chain, seventh account staked at runtime
  (`qau_stake`), committee-7 DKG completed on all seven nodes
  (activation epoch 5, group key prefix `7082d70f`); validator 7 then
  unstaked in full, the remove rotation completed on the six survivors
  (activation epoch 7, **same group key prefix `7082d70f`**, committee
  size 6) — deduping across both events the join+remove round trip
  preserved the group key exactly as R77 requires. Node roster captures
  covered every epoch of the chain (entries 6,6,7,7,7,6,6), including
  the epochs whose boundary slot produced no block (captured at the
  epoch's first canonical block per the R101 anchor rule).

  `.local-only/scripts/_r77net_*.ps1` drives a six-genesis-validator chain,
  stakes a seventh funded account at runtime (`qau_stake`, self-signed), and
  later fully unstakes it. The runtime-join path surfaced and fixed one real
  integration gap (this section's R76 follow-up): the staking-tx sync
  registered the validator in QPOS/ValidatorManager but left the QPOS
  validator's base Dilithium3 identity bytes empty, so every subsequent
  epoch roster capture failed closed with "no usable Dilithium3 identity
  key". `syncStakingFromBlock` now mirrors the transaction's public key
  into the consensus validator set (`QPOS.AttachValidatorPublicKey`,
  first-key-wins, malformed lengths refused;
  `consensus/r77_runtime_join_pubkey_test.go`). With that, the committee-7
  fresh DKG completes on all seven nodes on the live chain
  (`.local-only/tmp/r77net` evidence buckets).
  A second integration defect found by the same run: the remove-rotation
  probe compared the stored share's OLD participant id against the NEW
  committee's numbering, so only survivors whose roster position did not
  shift (members before the leaver in sorted order) ran the rotation while
  everyone else fell through to the fresh-key ceremony. The probe now tests
  membership by validator address against the old committee's identity
  bindings (`tryTDilithium3ReshareRemoveRotation`).
  A third integration defect: the remove plan itself picked the leaver off
  the *numeric* participant ids, and committee participants are
  (roster-position + 1) per committee — so a removed address was always
  mislabelled as the highest id when any survivor's numbering shifted. The
  probe now computes the leaver by address intersection over the old/new
  rosters and hands the same plan to the ceremony runner
  (`tdilithium3ReshareRemoveConfig.Plan`), which no longer recomputes it.
  A fourth integration defect (2026-10-04, found on the leave segment):
  the epoch-roster capture hook fired only on blocks whose slot was the exact
  epoch boundary, so every missed boundary slot permanently skipped that
  epoch's snapshot and every session anchored on it failed closed with
  "no snapshot captured" — the devnet missed 16 of 31 boundary slots on a
  degraded chain. The hook now follows the R101 epoch-boundary-root rule:
  when the boundary slot produced no block, the epoch's FIRST canonical block
  captures the roster anchored at that block's parent hash (the chain tip at
  the boundary), byte-compatible with the root rule
  (`node/tdilithium3_dkg_epoch_roster.go`,
  `TestTDilithium3DKGCaptureHookCoversMissedBoundarySlot`).
  A fifth integration defect (same rerun): the threshold share store pinned
  the numeric participant id at the candidate head, the ledger head, and the
  activation path, so a membership change in front of a survivor in canonical
  roster order bricked both admissible renumberings — the fresh-key rekey
  ("threshold candidate identity or generation rollback") and, one layer
  later, the same-key rotation. The id is roster-position-derived, not an
  identity primitive; the store now enforces only generation/committee-version
  rollback, in-generation group-key changes, and equal-version byte conflicts
  (`node/threshold_share_store.go`, `node/threshold_activation.go`,
  `TestThresholdShareStoreRenumbersParticipantOnCommitteeChurn`).
  A sixth integration defect (the acceptance-blocking livelock, found on
  the 21:19Z chain): the activation path re-verified the ALREADY-STORED
  certificate against the CURRENT roster-bound verifier. After any committee
  change the old acks are signed by the OLD committee's numbering, so the
  re-verification refused every new-certificate adoption with "invalid
  Dilithium3 v1 DKG activation certificate", stranding all incumbents while
  the freshly-joined member completed alone. The stored certificate is only
  re-verified now when its committee digest equals the incoming one
  (`node/threshold_activation.go`); the epoch-monotonicity and lineage
  guards are unchanged. A seventh, exchange-reliability cluster: the
  activation-ack collection sink was sized for the fixed six-member
  committee, so a seven-member ack burst overflowed and stranded collectors
  at 6/7; the sink scales with the committee now, stale/foreign-session
  envelopes are dropped with a diagnostic instead of aborting assembly, and
  the acknowledgement re-broadcasts every second until the quorum forms
  (`node/tdilithium3_dkg_activation_exchange.go`).
  The previously bare certificate sentinel
  (`ErrInvalidDKGActivationCertificate`) now reports which structural or
  per-acknowledgement check failed
  (`wallet/tss/protocol/dilithium3v1/activation_certificate.go`), which is
  how the sixth defect was identified from the node logs.
  An eighth finding from the R77d round (open; it is a design decision, not
  a bug): the remove rotation's stored share KEEPS old participant ids
  (`ResharedShare` does `ParticipantID: old.ParticipantID` because delta
  targeting references new positions but identity continuity matters for
  the ack chain), while every later epoch derives committee ids as
  roster-position+1 per session-derivation D2 — after a 7->6 rotation the
  stored committee {1,3,4,5,6,7} and the derived committee {1,2,3,4,5,6}
  disagree, and `LoadActiveAtEpoch`'s identity-bindings verifier rejects
  pid 3 (the persisted evidence carried a collision worth one id shift).
  Devnet evidence: on the first R77d-clean chain the rotation completed but
  `identity signature does not verify for participant 3` appears whenever a
  post-rotation session tries to source its own committee roster. Fix
  candidates recorded here as an explicit fork; RESOLVED 2026-05 same day by
  option (a), realised as: the activation record is now self-describing (v2)
  and stores the pid -> identity-key bindings it was verified under, so a
  post-rotation session verifies any stored certificate against the recorded
  map instead of re-deriving a verifier from the current roster view.
  Implementation at `node/threshold_activation.go` (v2 record),
  `node/threshold_protocol_paths.go` (unchanged file layout), and the two
  exchange commit points (`node/tdilithium3_dkg_activation_exchange.go`),
  whose callers now pass the session's identity bindings straight through.
  Option (b) — session-scoped preserved pids — stays dismissible: continuity
  lives at the address layer, and every chain state stays derivable from the
  roster alone.
 (a) identities-preserving normalization — activation commits
  the rotated share with fresh position-derived ids and the certificate
  path re-binds acks by validator address; (b) identity continuity — the
  session layer treats the active committee's id set as the committee
  source of truth and the D2 list becomes {position's preserved id}. The
  seam-level same-key signing evidence is unaffected either way; the fork
  only decides rotation-COMMITTEE durability across epochs.


## 6a. R77c follow-up — the topology redesign a same-key ADD needs **DESIGN NOTE**

The measured closure in section 7 proves the concentrated weave correction
cannot sign under any parameter row of the C=7 family. The one redesign
family that stays inside the CNF-RSS construction is to stop weaving the
joiner's groups fresh at all:

- **Rehearsal-carried components.** Delay the join by one epoch: during the
  pre-join epoch the incumbent committee runs the reshare folds from the
  CURRENT committee into the PHANTOM groups that a candidate joiner would
  occupy (the group masks are public knowledge as soon as the candidate's
  stake is in the activation queue, which is deterministic one epoch ahead).
  Every folded component lands at multiplicity 2 — the same profile the
  remove rotation already signs under — so the add rotation reuses the
  proven fresh rows instead of carrying a new halo.
- The joiner never holds fresh secrets in this shape: its components are
  inherited through the same fold-delta exchange the remove rotation uses,
  and the incumbent majority's zero-knowledge statement is unchanged (the
  fold's privacy argument is the one already reviewed for R77b, because the
  correction mass per component is 1+1, not 1+19).

Open proof obligations before this becomes a parameter row:

1. The CNF access-structure privacy argument assumes components are iid at
   fold time; a rehearsal-carried family derives them from the prior epoch's
   transcript, so the joiner's view of its own woven pieces needs an explicit
   independence lemma (the same caveat noted for telescoped pairwise
   differences in section 7).
2. The weaving correction becomes unnecessary by construction, which removes
   the correction group's special-case role — the plan verifier and the
   assembler get simpler, not more complex, which is the direction a lasting
   design should keep.
3. Joining becomes a two-epoch march (stake-finalized at epoch E-2, rehearsed
   at E-1, served at E+1); the queue already tolerates epoch-granularity
   activation, so this changes nothing user-visible.

Status: not scheduled; this section exists so the next design round starts
from a measured feasibility envelope instead of folklore. The fresh-key join
path shipped in R77 is the supported route and carries none of these
obligations.

## 7. Out of scope (explicit)

- Committee sizes 8-12 signing parameter rows (R76b pins `{6, 7}`).
- Committees built from discontinuous roster positions (the sampler keeps
  the roster's leading slice; see R76 section 8).
- Multi-position membership deltas within one epoch (fresh-key fallback).
- **R77c (resolved 2026-10-05 as measured-infeasible, not pinnable):** the
  signing-parameter row for rotated committees in the add shape cannot be
  pinned within the mode3 envelope. The derivation script
  (`node/.local-only/scripts/r77c_rotated_row.go`, the multiplicity-aware
  generalization of the R76b family procedure) reproduces the pinned C=7
  fresh row bit-for-bit at fold=1 (B=779.31, r=402748.8, r'=402847.0,
  Phint≈0.50, J=43) and then measures the add-rotated bearer party. The
  correction component's true multiplicity in the shipped plan is the number
  of NON-correction joiner groups, binom(6,2)-1 = 14 (the earlier "19" in
  this text was a topology miscount: weave groups are the 3-member groups
  containing the joiner). With profile owned=7 and one multiplicity-14
  component the bearer's aggregate coefficient mass is sqrt(20/7) = 1.69
  times the fresh profile (B=779.31 -> ~1317). Across the exponent grid the
  required HRej ball either breaches the z-bound headroom (P1=0.05 at the
  pinned exponent 4.95, r≈680k) or starves the fixed hint channel
  (expo 7.2: P1=0.987 but Phint=0.265; expo 8.4: P1=1.0, Phint=0.50 but
  pSession=0.003, J≈467 slots, ~3.5 MB of wire per party per request) — past
  the C=8 row already rejected as non-operational at J≈265 / 2 MB.
  The mass is structural: WeaverCorrection replaces one group's component
  with the negated aggregate of the other joiner groups so the family sums
  to zero, and every five-of-seven quorum hosts a correction-group member,
  so no parameter row of this family carries the add shape's signing.
  R77d addendum (the missing row the remove shape needed): the acceptance
  evidence folded into the driver above asserted key preservation, and the
  rotation seam then kept failing at the signing step until the signing
  family gained the rotated profile row. Measured mechanism: the pinned
  fresh row's radius margin (r'-r ≈ 82.9 at the C=6 row) is exactly sized
  for the eta=1 fresh shift; a rotated share's fold mass sqrt(2)-scales the
  per-signer challenge shift so every candidate overshoots and all 11 slots
  reject — deterministic starvation, not flake. The rotated C=6 row repins
  (expo 4.50 → M=2.1810, B=931.45, r=424037.5, r'=424155.0, Phint=0.5995,
  J=26 within the 43-slot transport budget; P1=1.0/P2=1.0), selected by the
  share profile — any active share carrying fold multiplicity > 1 selects
  it, all rotated shares of one rotation carry the marks identically, so the
  session never splits (`dilithium3v1.SigningParametersForShares`, pinned in
  `wallet/tss/protocol/dilithium3v1/params.go`, covered by
  family_r77d_test.go). The remove-rotation seam's end-to-end signature
  (produced on rotated shares, verified under the never-rotated group key)
  then passes with the row in place.

  Same-key ADD signing therefore needs a resharing-level redesign, and the
  natural one is also measured: cycle-difference spreading (replace every
  weave component k by the difference fresh_k - fresh_{pi(k)} along a
  permutation of the weave family, so the family still sums to zero but no
  component exceeds multiplicity 2) puts the worst party at mass ratio
  sqrt(2) = 1.41x fresh (owned=7 at multiplicity 2 each), and that row still
  fails the family's own gates: at expo 5.85 the hint channel measures
  Phint=0.22 (health band requires >=0.4 and the C=7 fresh row sits at
  0.505), with J≈183 slots at degraded margin and ~1.4 MB per party — and
  the trend only worsens inside the healthy band. The blocker is not the
  correction's placement but the C=7 family's radius sensitivity: any
  unfold-shaped multiplicity mass inflates the ball past what the fixed
  gamma2/omega hint channel tolerates. A genuinely additive same-key
  rotation would need a topology where joiner-family mass stays at
  multiplicity 1 (e.g. joiner components derived from rehearsal-carried
  material rather than freshly woven values) — a protocol-level change,
  not a parameter row. That is beyond this line's scope. What ships instead: joins run the fresh-key ceremony (new key, fully
  supported), and the remove shape's same-key rotation signs under the
  pinned fresh rows because its fold multiplicity stays <= 2, which the
  measured geometry tolerates. The wallet and runner layers stay
  multiplicity-exact; the acceptance path remains gated and now fails with
  the measurement cited here.

  Addendum, same day: the obvious "spread the correction across the weave
  groups instead of concentrating it" variants are ruled out, by
  conservation AND by measurement. The correction's value is the negated
  sum of the 14 non-correction weave components (an earlier draft of this
  note said 19 from a topology miscount), so 14 units of coefficient mass
  exist no matter how they are divided. Every weave group contains the
  joiner, so every piece of the correction lives on the joiner's share and
  its per-share total is invariant at 28 (14 fresh + correction) — but the
  signing-relevant bound runs on the per-attempt allocation (at most 7 owned
  groups per party), under which the measured best spread variant
  (cycle-difference, every component at multiplicity <= 2) tops the worst
  party at mass ratio sqrt(2) = 1.41x fresh — and the grid measures even
  that row outside the families gates (at expo 5.85: Phint 0.22 against the
  >=0.4 health band of the C=6/C=7 pinned rows, J ≈ 183 slots at ~1.4 MB of
  wire per party; stricter acceptance only drives J up). Neither placement
  nor parameter choices rescue the add row inside this topology. The remaining exits are protocol-level and carry new
  proof obligations: a weave family whose components are jointly sampled
  zero-sum at the value level (e.g. telescoped pairwise differences keep
  every component at difference-of-two mass BUT make adjacent components
  correlated, which the CNF access-structure privacy argument does not
  presently cover), or a different add construction altogether. Either is a
  construction spec of its own, with an independence/privacy analysis, not a
  parameter row — until then the add shape routes to the fresh-key ceremony
  by design and the remove shape carries the same-key property alone.

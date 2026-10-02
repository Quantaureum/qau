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
  into one component with multiplicity 19, so the pinning of the R57
  HRej radius (`eta=1`, C(6,3)=20 fresh groups) must gain its rotated row
  before a quorum hosting the correction group signs at acceptable odds.
  Remove-shape signing is unaffected (fold multiplicity <= 2) and fully
  accepted.
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
- **Devnet acceptance (`r77net*`):** start six validators, form the chamber
  under R76, then onboard validator 7 so the epoch-(e+1) roster has seven
  members; reshare the key to the seven-member committee; verify the group
  public key is identical across the boundary; observe the four-of-six
  committee cease to suffice and the five-of-seven committee sign seals
  with the *same* group key. Then rotate validator 7 out: the threshold
  falls back to four-of-six with the key still identical. The run asserts
  that no share store ever holds two adopted generations of the key.

## 7. Out of scope (explicit)

- Committee sizes 8-12 signing parameter rows (R76b pins `{6, 7}`).
- Committees built from discontinuous roster positions (the sampler keeps
  the roster's leading slice; see R76 section 8).
- Multi-position membership deltas within one epoch (fresh-key fallback).
- **R77c (open):** the signing-parameter row for rotated committees in the
  add shape. The correction component's multiplicity is
  binom(C-1, g)-1 = 19 at C=7, so the per-signer challenge-shift bound and
  HRej radius must be re-derived for the hybrid multiplicity profile
  (carried 1 + fresh 1 + correction 19). The wallet and runner layers are
  already multiplicity-exact; only the acceptance path is gated.

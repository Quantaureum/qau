# QAU Threshold Dilithium3 v1 Signing MPC Specification

**Status:** Design note; defines the release gate for the v1 signing backend

**Date:** 2026-09-26

## Purpose

This note fixes the signing construction for `ThresholdProtocolDilithium3V1` over
the CNF replicated secret sharing defined in
`2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`.

It exists because the existing v1 code contains no production signing path. The
only response-combination code in the tree lives in test files
(`sign_combine_test.go`, `sign_combine_probe_test.go`), and both are explicitly
labelled `DEVNET ONLY ... not a secure signing protocol`. This note explains
*why* that construction cannot be promoted, and fixes what must replace it.

Scope:

- define the exact mode3 signing and verification equations the backend must
  reproduce;
- define the public/hidden boundary and prove the leakage results that force it;
- define the nonce, rounding, norm, hint, and challenge subprotocols;
- define the rounds, state machine, abort and burn rules;
- define the view of a malicious coordinator plus two corrupt participants;
- list the open obligations that remain between this note and an enabled
  backend.

It does not claim production readiness, and it does not implement anything. The
credential format, key layout, DKG, and journal are already fixed elsewhere and
are not revisited here.

## Fixed Parameters and Identity

The backend targets the legacy CIRCL Dilithium mode3 profile used by the chain:

```text
N = 256          Q = 8380417      K = 6            L = 5
Eta = 4          Tau = 49         Beta = 196       Omega = 55
Gamma1 = 2^19 = 524288           Gamma2 = 261888  D = 13
CTildeSize = 32                  public key 1952 bytes
signature 3293 bytes             threshold exactly four of six
active corruption bound: two participants, plus a fully malicious coordinator
```

Committee positions are canonical `0..5`. All 20 three-member group masks, the
`AllocateRSSGroups` assignment, the signing session identifier, and the signing
journal are defined in the sibling documents and are used unchanged. The
threshold-signing hyperball parameters (`eta`, `phi`, `nu`, `expo`, `M`, `B`,
`r`, `r'`, `J`) are part of the same fixed profile; their pinned values and
derivation are in "Per-Party Rejection Parameters (R57)".

## Reference Equations the Backend Must Reproduce

Signing inputs: `rho` and `t1` are public; `s1 ∈ R^L` and `s2 ∈ R^K` are the
shared small secrets; `t0` is **not** stored by the backend.

The verifier's equations are unchanged and are the acceptance target:

```text
tr      = SHAKE256(pk)[0:32]
mu      = SHAKE256(tr || msg)[0:64]
w1      = HighBits(w)           (K*N values in [0,16))
c_tilde = SHAKE256(mu || EncodeHighBits(w1))[0:32]
c       = SampleInBall(c_tilde)          == DeriveMode3Challenge(c_tilde)
accept iff UseHint(h, HighBits(A*z - c*t1*2^D)) == w1 and ||z||inf < Gamma1 - Beta
```

In the threshold construction (R57) `w = sum_i w_i` and `z^(1) = sum_i z_i^(1)`
are sums of published parts; the verifier sees only the packed
`(c_tilde, z^(1), h)`. The pre-R57 single-signer quantities (`y` as one uniform
vector, the additive `u_p`, the shared carry) are retired and are kept only in
the history sections of this note.

Verification is unmodified `mode3.Verify`, i.e. it recomputes

```text
w' = A*z - c*t1*2^D
accept iff UseHint(h, HighBits(w')) == w1     and ||z||inf < Gamma1 - Beta
```

The backend must therefore produce `(c_tilde, z, h)` such that the public
verifier's `w1'` equals the `w1` that was committed into `c_tilde`. Nothing
about the verifier changes.

`HighBits`, `LowBits`, `MakeHint`, `UseHint`, and `Power2Round` are the exact
semantics of `wallet/tss/protocol/dilithium3v1/rounding.go`, which is the local
reference for mode3 decomposition. Every subprotocol below is specified against
that reference and must be validated by vector tests against it, not against a
re-derived approximation.

## Public / Hidden Boundary

This is the central invariant of the whole design. The R57 revision changes it
in one deliberate way: the aggregate commitment `w` is now **public by design**,
because each signer publishes its own commitment share `w_i` as a full MLWE
sample before the challenge is derived.

**Public by design (and safe):**

- `rho`, `t1`, the 1952-byte public key, and the transcript digest;
- the signing session identifier and the exact sorted participant set;
- every round-1 commitment digest, every revealed `w_i`, and therefore the
  aggregate `w = sum_i w_i` with all of its low bits;
- `w1 = HighBits(w)`, because `c_tilde` binds it and the verifier recomputes it;
- `c_tilde`, `c`, the accepted aggregate `z^(1)`, the reconstructed `delta`,
  the final `h`, and the 3293-byte signature;
- every accepted per-signer response part `z_i^(1)`: the aggregation opens
  exactly those, and the per-party rejection lemma is what makes them safe;
- every pass/fail bit that the protocol is defined to open (rejection, abort
  reason codes, evidence digests).

**Never public, in any round, to anyone, including the coordinator:**

- the raw ball point `(x1_i, x2_i)` behind `r_i`, and in particular the second
  part `x2_i` in any individual form;
- the unexpanded first randomness `nu*x1_i` separately from the masked
  response `z_i^(1)`;
- a rejected slot's response `z_i^(1)`, and the second part `z_i^(2)` of any
  signer in any slot;
- `y_i`, `e_i`, and the residual error that the `w_i` reveal leaves hidden;
- `s1`, `s2`, their per-position component sums, every stored component, and
  every partial secret `spart_i`;
- `t0`, `t1` intermediate values, and the complete private-key encoding.

Publishing `w` is not a concession: `w_i = A*r_i^(1) + r_i^(2)` is a fresh MLWE
sample whose second part shields the first, and the accepted `z_i^(1)` is kept
independent of `spart_i` by the per-party rejection lemma. The next section
states the leakage results that force both properties, and rules out the
shortcut of publishing `A*r_i^(1)` alone.

## Leakage Results (Negative Results That Fix the Design)

### Lemma 1 (matrix inversion)

`q - 1 = 8380416 = 2^13 * 1023` is divisible by `512 = 2^9`, so `X^256 + 1` splits
into 256 distinct linear factors over `F_q` and `R_q = F_q[X]/(X^256+1)` is
isomorphic to `F_q^256`. Under this isomorphism `A(rho) ∈ R_q^{6x5}` is 256
independent scalar `6x5` matrices. For a uniformly random `rho`, any fixed
5-row subset of `A` is invertible over `R_q` with probability at least
`1 - 256/q ≈ 1 - 3.1e-5`; all six 5-row subsets are simultaneously invertible
with probability at least `1 - 6*256/q`.

**Consequence.** For any `rho` produced by the DKG, the map
`y -> A*y` is injective with overwhelming probability, and there is an
efficiently computable right inverse on any 5 rows.

### Corollary 1 (never open `A*r_i^(1)` without the error)

If `A*r_i^(1)` alone becomes known, Lemma 1 gives `r_i^(1) = A^{-1}(A*r_i^(1))`.
The published response part `z_i^(1) = c*spart_i^(1) + round(nu*x1_i)` and the
public `c` then give `spart_i^(1) = c^{-1}(z_i^(1) - round(nu*x1_i))` whenever
`c` is invertible. This is why the round-2 reveal is the full sample
`w_i = A*r_i^(1) + r_i^(2)` and never `A*r_i^(1)` alone: the second part
`r_i^(2)` is the MLWE error that keeps the first hidden, and recovering `r_i`
from `(A, w_i)` is a Module-LWE instance.

### Corollary 2 (low bits are only safe because of the error)

`w = alpha*HighBits(w) + LowBits(w)` with `alpha = 2*Gamma2 = 523776`, so
publishing `LowBits(w)` reconstructs `w` exactly. In the revised construction
that is intended: `w` is public, and its safety rests entirely on the error
term of Corollary 1. What must never be echoed is any per-signer decomposition
of `w_i` into `A*r_i^(1)` and `r_i^(2)`, or the second part `z_i^(2)` of a
signer's response: those remove the MLWE shield from the per-signer view.

### Corollary 3 (a rejected slot publishes nothing, and randomness is single-use)

`z_i = c*spart_i + s_i` with `s_i = round(nu*x1_i, x2_i)`. A slot that fails any
signer's local rejection test publishes no `z_i^(1)` for that slot at all,
because the aggregation is aborted before any response is released. And if one
signer's `s_i` were ever reused under two different challenges `c` and `c'`,
the two published responses would give
`spart_i^(1) = (c - c')^{-1} * (z_i^(1) - z_i'^(1))` exactly. The single-use
rule is therefore load-bearing for the response as much as for the commitment:
fresh randomness per slot, one slot bound per attempt, and a burned record for
every aborted attempt.

### Corollary 4 (public `w` is an MLWE sample, not a leak)

Revealing `w_i = A*r_i^(1) + r_i^(2)` exposes no function of `s1` or `s2`: it is
a fresh MLWE sample whose secret half is one-time randomness. The ordinary
Dilithium verifier already publishes an equivalent object through `HighBits`,
and the reviewed construction's own reduction treats `w` as public. What stays
hidden is the second half before aggregation: `z_i^(2)` is never published, and
only its aggregate shadow `delta` appears in the combine.

### Corollary 5 (accepted `z_i^(1)` is safe by the rejection lemma)

The individual response part is released, so its safety cannot come from
secrecy of the aggregation. It comes from the per-party rejection lemma: for a
challenge shift bounded by `B`, the accepted `z_i` distribution is
`M`-close in smooth Rényi divergence to a fixed ball distribution that does not
depend on `spart_i`. The published first part is a fixed `nu`-scaling of that
accepted value, so the same bound covers it. No other value may be released in
round 3.

### Summary

Corollaries 1-3 rule out the previously written combination path in
`sign_combine_test.go`: that path opens `w_p` shares, sums them, and returns a
combined response, which is precisely the fatal pattern. The test files remain
in the tree **only** as an algebraic regression oracle with their existing
`DEVNET ONLY` warning, and must be unreachable from production code.

They also rule out the pre-R57 nonce design: a globally uniform nonce with
distributed rounding, a shared carry, and two global norm predicates. That
design is not merely expensive (its measured cost is quoted in the Cost
Envelope section); its round-2 opening had to be restricted to `w1` precisely
because opening anything more would have been fatal. The reviewed construction
removes the tension instead of working around it: public `w` that is an MLWE
sample, and a response whose rejection sampling is done locally by each signer.
That is what the rest of this note specifies.

## Secret Layout Used by Signing

Signing uses two different share structures, and they must not be confused:

1. **Long-term secret (replicated).** The global `s1`, `s2` are the sum of the
   20 CNF-RSS components. `AllocateRSSGroups(activeMask)` assigns exactly 5
   components to each of the 4 active positions, so every component is covered
   and no position holds more than 5. The assignment is deterministic and
   transcript-bound, and it is exactly the balanced partition `RSSRecover`
   produces in the reviewed construction (each signer signs with at most
   `ceil(C(6,3)/4) = 5` components). A signer's partial secret is
   `spart_i = sum of its 5 assigned components`, one half `spart_i^(1)` in
   `R^L` and one half `spart_i^(2)` in `R^K`.

2. **Per-slot randomness (independent per signer, one slot only).** Each active
   signer samples its own ball point `(x1_i, x2_i)` uniformly in
   `B_{L+K}(r')`, keeps it for exactly one slot, and publishes the MLWE sample
   `w_i = A*(nu*x1_i) + x2_i` after the round-1 commitment. Its response part is
   `z_i^(1) = c*spart_i^(1) + round(nu*x1_i)`, released only for a slot that
   every signer accepted.

Nothing in the online phase is computed on shared secrets. Every signer works
on its own values, and every value that leaves a signer is either a public
round message or a value the protocol is defined to open. The online
arithmetic is therefore: 4 hyperball samples, 4 `[A I]*r_i` products, 4
`c*spart_i` products (of which only the first half is published), one sum for
`w`, one sum for `z^(1)`, the public combine computations, and the public
hint. No distributed carry, no bit decomposition, no authenticated opening,
and no MPC circuit remain on the signing path; the pre-R57 machinery for them
is retired by the R57 revision.

## Nonce Shares, the MLWE Commitment, and Per-Party Rejection (R57)

This section replaces the pre-R57 "Nonce Generation, Reduction, and the Carry
Obligation". The construction is the reviewed one: no global uniform nonce, no
shared carry, no distributed norm circuits. The verbatim sources are recorded
in "Revision Record (R57)".

### Target distribution

The randomness of one signer in one slot is a *rounded imbalanced ball point*:

```text
chi_r = { round(nu*x1, x2) | (x1, x2) sampled uniformly in B_{L+K}(r') }
```

with `round` rounding each coordinate to the nearest integer, the first `L`
polynomials (the `x1` half) scaled by the expansion factor `nu`, and the second
`K` polynomials (the `x2` half) not scaled. The target set is the same shape at
radius `r < r'`. The imbalance exists because the hint technique only checks
the second half of the response, which would otherwise reject far more often;
`nu` enlarges the acceptance region of the first half while leaving the second
half's region unchanged.

`r' - r` is small (about 83 at our parameters), so the two balls nearly
coincide; the acceptance geometry is what makes `M = (r'/r)^{N*(L+K)}` the
natural divergence unit.

### The per-party rejection step

Let `spart_i = (spart_i^(1), spart_i^(2))` be the signer's partial secret from
the five assigned components, and `v_i = c * spart_i` the challenge shift. The
signer samples `(x1_i, x2_i)` uniformly in `B_{L+K}(r')` and applies:

```text
test   := (v_i^(1)/nu + x1_i, v_i^(2) + x2_i)
accept iff ||test||_2 <= r
response_i := (v_i^(1) + nu*x1_i, v_i^(2) + x2_i)   (first half published)
```

`accept` is a public bit; the response is published only for slots that every
signer accepted. `test` is a scaled copy of the response's first half combined
with the unshifted second half, matching the reference's `HRej` (Fig. 4) and
its implementation's difference of the first half by `nu` before the ball
test.

### The divergence bound and the acceptance

The analysis uses the smooth Rényi divergence of the reference's Lemma 2.4
(Devevey et al. [27] there): for any shift `v` with `||v||_2 <= B` and any
`r, r'` with

```text
2*eps = I_{1-1/phi^2}((N*(L+K)+1)/2, 1/2)
r'^2 >= r^2 + B^2 + 2*r*B/phi
```

it holds that `R_eps^inf( U(B(r)) || U(B(r', v)) ) = (r'/r)^{N*(L+K)}`, and for
every `M > 1` the choices

```text
r  = B * (1/phi + sqrt(1/phi^2 + M^(2/(N*(L+K))) - 1)) / (M^(2/(N*(L+K))) - 1)
r' = M^(1/(N*(L+K))) * r
```

give a divergence of at most `M`. The per-party acceptance probability is
`(r/r')^{N*(L+K)} = 1/M` (measured `0.5595` against the model `0.5596` at our
parameters, see the parameter section), and the per-slot acceptance
probability over the `T = 4` active signers is

```text
p = (1/M)^T = 2^(-expo),   expo pinned at 3.3
```

A signing request runs `J` independent slots in parallel (the reference calls
this number `K`; this note calls it `J` because `K` is already the mode3 row
dimension), each with fresh randomness for every signer, and takes the first
slot that every signer accepted and whose public combine checks pass.

### The coalition view

Let the adversary control the coordinator and two signers. It then knows the
two corresponding `w_i` reveals, their response parts, and everything the
coordinator routes. The reference's reduction shows this view is simulatable:
the `w_i` of the honest signers are MLWE samples whose second half is
one-time randomness, and the accepted response parts are `M`-close to a ball
distribution that does not depend on the partial secrets. Two invariants are
what the implementation must preserve, because the reduction does not survive
without them:

- **Fresh randomness per slot and per signer.** Corollary 3 is exact: one
  reused `s_i` under two challenges exposes `spart_i^(1)` outright.
- **No rejected value in any message.** A rejected slot's response, and every
  second half `z_i^(2)`, never leave the signer; only `delta` in aggregate
  (which is reconstructible from public values anyway) is used.

### Required properties

1. `(x1_i, x2_i)` is uniform in the ball of radius `r'` up to rounding; the
   sampler is part of the side-channel review, and a discretized sampler must
   be distribution-tested (see Open Obligations).
2. No coalition of the coordinator plus two corrupt signers learns any honest
   `(x1_i, x2_i)`, any honest `spart_i`, or any randomized value that is not
   one of the protocol's defined openings.
3. Randomness is single-use per slot and zeroized on burn, and a burned slot
   never contributes to a signature.
4. Sampling is constant time with respect to the sampled values.
5. A rejected slot publishes at most the acceptance bit; it never publishes a
   response, and the whole request is never allowed to produce a signature
   from a slot with a rejected signer.

### Rejected candidates

- **The pre-R57 design** (globally uniform nonce, shared carry, two global norm
  MPC circuits). Rejected on measured cost, and because it forced the round-2
  opening to hide everything beyond `w1`. Its numbers are kept in the Cost
  Envelope section as the reason this revision exists.
- **Publishing `A*r_i^(1)` without the second part.** Fatal by Corollary 1.
- **Dropping the second rejection predicate as an MPC circuit.** R55 rejected
  the *predicate removal* as unproven; R57 removes the *circuit* because the
  per-party rejection subsumes the conditioning the predicate provided, which
  is exactly what the reviewed reference does. The public `||delta||inf <=
  Gamma2` combine check remains.
- **Splitting the global bound `Gamma1 - Beta` evenly per signer** as a local
  bound. That variant had a per-attempt acceptance on the order of `exp(-112)`;
  it is a denial of service. The ball construction with the `nu` imbalance is
  the fix, not a bound split.
- **A single signer sampling the whole randomness and broadcasting it.** That
  opens the one-time pad and directly yields `c*spart_i`.

## High-Bit Extraction: Retired Circuit and In-the-Clear Evaluation (R57)

`w1 = HighBits(w)` is computed in the clear. Since `w = sum_i w_i` is public
after round 2, the distributed high-bit extraction circuit of the pre-R57
design is retired: its bit decompositions, its measured 80 shared
multiplications per coefficient, and the residue reuse that fed the pre-R57
`P2` are all gone from the signing path. The local rounding reference
`rounding.go` (`decomposeCoefficient`, `HighBits`, `MakeHint`, `UseHint`)
remains the normative semantics, and the exhaustive vector tests built for the
old circuit stay in the tree as the regression oracle for the in-the-clear
evaluation against that reference.

The equations the backend must reproduce are in "Rounds, Messages, and State
Machine". What follows is the retired circuit, kept as history because its
tests are reused.

### The retired circuit

The algebraic anchor is the exact identity

```text
Gamma2 = (Q - 1) / 32        =>    alpha = 2*Gamma2 = 523776
Q = 16*alpha + 1
```

so on the canonical residue `s ∈ [0, Q)` the high part is
`round(s / alpha) mod 16` away from the single wraparound case at `Q - 1` that
`decomposeCoefficient` handles explicitly. This replaces a general secret division with a fixed boolean circuit that
evaluates the reference formula on authenticated bits; no interval search and no
data-dependent branches are involved.

The reference formula in `decomposeCoefficient`, on the canonical residue, is

```text
h7   = (canonical + 127) >> 7
high = (((h7 * 1025) + 2^21) >> 22) & 15
```

The only non-linear step is `(canonical + 127) >> 7`; everything after it is a
fixed linear circuit on the resulting bits. The distributed evaluation is:

1. **Bit decomposition.** A dealer-provided uniform mask `r ∈ [0, Q)` is shared
   bit by bit (23 bits per coefficient). The signers open `d = value - r mod Q`,
   add `d` back through a public-addend ripple carry adder over 24 bits, add the
   public constant `2^24 - Q` whose carry out is the reduction bit
   `g = [r + d >= Q]`, and undo the wrap by adding `(1 - g)*Q` back modulo
   `2^24`. The result is the canonical residue `r + d - g*Q`, whose bit 23 is
   provably zero, so 23 bits suffice. Measured: 80 shared multiplications and
   one opening per coefficient.
2. **Shift.** `t = OR(bits[0..6])` is exactly the carry produced by adding `127`,
   and `F = (bits[7..22]) + t` is a 17-bit shared value with top bit the carry
   out; `F` is bounded by `65473`.
3. **Scale.** `F*1025 = F + (F << 10)` is a 27-bit shared addition; adding the
   constant `2^21` recomputes only the top cells. The result bits 22..25 are
   `high = u & 15` where `u = (F*1025 + 2^21) >> 22 <= 16`; bit 26 is
   discarded, which is exactly the `u = 16` case where the reference wraps to
   `high = 0`.
4. `high` is opened. It is `w1` and it is the only value this subprotocol opens.

For `P2` the same bits are reused without a second decomposition: once `high` is
known the low quantity is linear,

```text
lowResidue = canonical - sum over i of high_i * (2^i * alpha)
```

and its canonical residue equals the canonical residue of the centered
`LowBits`, because centering changes the integer representative but not the
residue modulo `q`.

The retired subprotocol had to satisfy:

- operate on authenticated additive shares of `w` over `Z_q`;
- reproduce `decomposeCoefficient` bit-exactly, including the `Q - 1` boundary
  case, verified by exhaustive vector tests against `rounding.go`;
- open exactly `w1` (the 16-valued high part) and nothing else;
- never open `LowBits(w)`, any carry vector, or any intermediate comparison
  that is a function of a single coefficient of a secret value;
- remain correct against a malicious coordinator and two corrupt signers,
  meaning every intermediate must carry a MAC and every opened value must be
  checked.

Reference implementation of the retired circuit: `mpc_arithmetic.go`. It is no
longer on the signing path; its disposition is Open Obligations item 8.

## Component Bound Decision (R57)

### The problem, restated for the revised construction

The CNF-RSS aggregate secret is the sum of 20 component draws, so its
distribution is never the native one whatever the component bound is. The bound
now decides two quantities of the revised construction:

- the per-party shift bound `B = 1.3 * sqrt((K + L/nu^2) * N * 5) * sigma_eta *
  sqrt(Tau)`, proportional to `sigma_eta = sqrt(((2*eta+1)^2 - 1)/12)`, and
  through it the ball radius `r` and the published response scale;
- the lattice-norm gap between the aggregate secret and the native mode3
  secret, which is what the residual re-estimation obligation measures.

With the pre-R49 bound `Eta = 4` the aggregate has support `+/-80` and standard
deviation about 11.55 (4.5x native). With the R49 bound `+/-1` it has support
`+/-20`, standard deviation about 3.65 (1.41x native), and entropy 3.208 bits
against the native 3.170.

### Decision (R57): the component bound stays at `+/-1`

`RSSComponentEta = 1` is unchanged by R57. Reasons, in the order that matters
now:

- The revised construction's cost is set by `B`, and `B` is proportional to
  `sigma_eta`: `+/-1` gives `B = 658.64` against `2082.79` at `Eta = 4`. The
  same acceptance target therefore needs radii and a published response scale
  about 3.2x smaller, and the parameter section's search lands at `J = 11`
  slots where the reference's own `Eta = 4` parameter set needs `J = 804`.
- The lattice-norm gap is the smaller one (1.41x native against 4.5x), which
  matters because the residual re-estimation below is the only security
  obligation this note leaves open.
- Nothing in the revised construction requires the native component bound.
  The reference's own `RSS` samples each component from `U([-eta, eta])`; the
  `+/-1` bound is that same sampler with a tighter `eta`, and every derived
  quantity (the aggregate bound, `Beta_eff` as a historical bound, the
  sampler's support) is recomputed from it.

### Consequences carried into code by R58

- `RSSComponentEta` and `RSSAggregateBound` remain the sampler and validation
  constants.
- `BetaEffective`, `NormBoundZ`, and `NormBoundR0` belong to the retired global
  norm checks: they leave the signing path in R58. The public combine checks use
  the verifier's own native `Beta = 196` and `Gamma2`.
- The 3293-byte signature format is unaffected, and the DKG component tests
  keep their existing bound.

### Residual obligation: lattice security re-estimation

The aggregate secret has standard deviation 3.65 against the native 2.58, a
factor of 1.41. Lattice security depends on the secret's norm, not its entropy,
so this is a real change and the mode3 parameters must not simply be carried
over. The required work is:

1. express the exact aggregate coefficient distribution (the 20-fold convolution
   of the uniform distribution on `{-1, 0, 1}`, with maximum probability 0.1082,
   support `[-20, 20]`);
2. re-estimate the Module-LWE hardness for `K = 6`, `L = 5`, `N = 256`,
   `Q = 8380417` with that secret distribution as the primal-attack target;
3. confirm the resulting margin still clears the level the legacy profile
   targets, and record the estimate and the estimator invocation used.

No numeric security claim may be published for this backend before step 2 is
done. The sampler bound and every signing parameter derived from it (the
parameter section's table) are frozen; the security estimate is a separate
deliverable and does not change the arithmetic.

## Per-Party Rejection Parameters (R57)

This section replaces the pre-R57 "Distributed Norm Checks". Those circuits
evaluated two global predicates `P1` and `P2` on authenticated shares while
opening one bit each; in the revised construction both are gone from the MPC,
`P1` and the `delta` bound survive as public combine checks on public values.

### Derivation method

The parameters follow the reviewed construction's own parameter procedure
(`params/hyperball.sage` in the reference implementation): pick the component
bound `eta` and the smoothing factor `phi`; set the target per-slot acceptance
`p = 2^(-expo)` for `T = 4`; compute `M = (1/p)^(1/T)`; compute the shift bound
`B = 1.3 * sqrt((K + L/nu^2) * N * 5) * sigma_eta * sqrt(Tau)`; solve the ball
geometry for `r` and `r'`; estimate, by Monte Carlo over the accepted-randomness
model, the probabilities of the three public combine checks; and set
`J = ceil(ln 2 / -ln(1 - pfinal))` parallel slots so that one execution of the
request succeeds with probability at least `1/2`.

The derivation was re-run locally against this repository's rounding reference,
with two validations:

- running the reference's published `(4,6)` mode3 row through the same code
  from its own inputs (`eta = 4`, `phi = 8`, `nu = 6`, `expo = 8.8`) yields
  `B = 2082.79`, `r = 488704.3`, `r' = 488969.0` against the published
  `488704 / 488969`, and `J = 812` against the published `804` (the difference
  is Monte Carlo resolution in the check probabilities, about 1%);
- the per-party acceptance model `1/M` matches a direct simulation of `HRej`:
  `0.5595` measured against `0.5596` at our parameters, and `0.2200` against
  `0.2176` at the reference's `(4,6)` mode3 row. The reference's published
  acceptance exponents for all five `(T, 6)` mode3 rows are reproduced by
  `p = M^(-T)` to the published precision.

### Pinned parameters

| parameter | value | note |
|---|---|---|
| component bound `eta` | `1` | `RSSComponentEta`, unchanged from R49 |
| smoothing `phi` | `8` | `2*eps < 1.39e-16` at `N*(L+K) = 2816` |
| expansion `nu` | `6` | the reference's mode3 value |
| target exponent `expo` | `3.3` | `p = (1/M)^T = 2^-3.3 = 0.10153` |
| divergence `M` | `1.7715` | `M = (1/p)^(1/4)` |
| shift bound `B` | `658.64` | `1.3` margin over the RMS norm |
| test radius `r` | `407958.8` | `HRej` accept radius |
| sampling radius `r'` | `408041.6` | `r' - r = 82.8` |
| per-party acceptance | `0.5645` model | `1/M`; measured `0.5759` |
| per-slot acceptance `p` | `0.10153` | all four signers accept |
| check `\|z^(1)\|inf < Gamma1 - 196` | `1.0000` | 40k samples |
| check `\|delta\|inf <= Gamma2` | `1.0000` | 40k samples |
| check `\|h\|1 <= Omega` | `0.6506` | 40k samples; the binding one |
| per-slot success `pfinal` | `0.06606` | `p * P1 * P2 * Phint` |
| parallel slots `J` | `11` | `ceil(ln 2 / -ln(1-pfinal))` |
| success per request | `0.528` | `1 - (1-pfinal)^J` |

Expected slots per accepted signature: `1/pfinal = 15.1`. Expected request
executions per accepted signature: `1.90`.

### Verification of the pinned point

- The measured per-party acceptance (`0.5759` over 20k samples) is slightly
  above the `1/M` model, because the actual shifts are typically below the
  `1.3*RMS` bound; taken at face value it would allow `J = 10`. `J = 11` is
  pinned deliberately: it is the value from the model acceptance, which is the
  one the analysis provides, and the measured figure is not a proven bound.
- The hint-weight check is the binding constraint (mean hint weight about 53
  against `Omega = 55`), and it varies with the key's `t0` realization: over 40
  sampled keys the joint `P2 * Phint` probability stayed in `[0.605, 0.688]`
  around a median `0.655`, and every one of those keys still gives `J = 11`. A
  failing check is a public abort of that slot, never a correctness risk.
- `P1` and `P2` are far from their bounds: the observed worst `|z^(1)|inf` and
  `|delta|inf` keep factors of about 1.5 and 3 below their limits, so they are
  not binding and their estimates are robust.

### Caveats that must stay in the record

- `B` uses the reference's `1.3x` margin over the RMS norm; it is a
  parameter-selection convention, not a proven tail bound, and the
  construction's own correctness statement is probabilistic in the same way.
- The check probabilities are Monte Carlo estimates over the
  accepted-randomness model the reference uses (accepted samples modeled as
  uniform in the target ball), with the sample sizes stated above; they are
  engineering estimates, not proofs.
- The lattice-norm gap of the `+/-1` aggregate (1.41x native) is the remaining
  security obligation, unchanged by R57.

## Cost Envelope (R57)

The revised design has no MPC on the signing path: no shared multiplications,
no openings beyond the public round messages, and no preprocessing supply. The
cost is local arithmetic plus the public unveilings.

Per slot, message bytes per party (the reference's counting convention; `23`
bits per `w` coefficient, `20` bits per response coefficient):

| artifact | bytes |
|---|---|
| round-1 commitment digest | 32 |
| `w_i` reveal (`K` mode3 polynomials) | 4416 |
| `z_i^(1)` reveal (`L` mode3 polynomials) | 3200 |
| slot total | 7648 |

Per slot, local arithmetic per signer: one uniform ball sample in dimension
`N*(L+K) = 2816` with rounding, `[A I]*r_i` (30 ring multiplications),
`c*spart_i` (11 ring multiplications, only the first half published). The
combine adds one `A*z^(1)` (30) and 1536 hint evaluations, and finalization
runs one more `A*z^(1)` inside the end-to-end verification.

Per signing request: `J = 11` slots, so `32 + 11*7616 = 83808` bytes per party
by the convention above, or about 69 kB on average since only accepted slots
reveal `z_i^(1)` (0.576 of slots per party). Per accepted signature: 1.90
request executions on average, so about 160 kB by the convention (about 131 kB
on average). The reference's own `(4,6)` mode3 parameter set needs 6.12 MB per
party per request; the difference comes from the `+/-1` component bound and
the re-derived `expo`, not from a different construction.

The comparison with the retired design is not like-for-like, and the record
should say so: its `877822` figure counts authenticated multiplications (MPC
gates), while the revised figure counts plain ring multiplications. The order
is what matters: 41 plain multiplications per signer per slot against 877822
authenticated ones per attempt.

### Retired design (history, R52-R56)

The pre-R57 design needed 2816 shared bit decompositions per attempt (1536 for
`w`, 1280 for `z`, plus its own decomposition of `w - c*s2`), pinned by
`TestMPCArithmeticCostEnvelope` at 80 shared multiplications per bit
decomposition, 129 per HighBits coefficient, and 125 per norm check, and the
whole attempt was pinned by `TestThresholdSigningAttemptCostEnvelope` at
**877822 shared multiplications and 1770238 openings**. With the joint
acceptance of its two global predicates at about `2.9e-4` (roughly 3400
attempts per accepted signature), one signature cost on the order of `3e9`
shared multiplications and `6e9` openings, which the executor note then
measured at about 190 GB of authenticated share traffic before framing. The
executor note's R54 correction also stands: an earlier claim of "about 1e8
shared ANDs per signature" was wrong by a factor of thirty. Those figures are
why R57 exists.

Those pre-R57 figures supersede the earlier table-driven envelope of this
section; nothing from that envelope is on the signing path anymore.

## P2 Necessity Review (R55)

The cost finding above asked whether the second rejection predicate `P2` on
`LowBits(w - c*s2)` must be evaluated inside the MPC at all: it accounts for
roughly 44 percent of the measured per-attempt work, and its removal would
return the acceptance rate to `9.1e-2`, about eleven attempts.

Findings on our side:

1. `P2` is a signer-side rejection rule. The unmodified verifier never checks
   it: mode3 verifies `||z||inf < Gamma1 - Beta` and the hint equation only,
   and R53's interop tests already produce accepted signatures whose hints are
   derived in the clear from `w1` and `w' = A*z - c*t1*2^D`.
2. `h` is a public function of `(w1, z, c, t1)`: `w'` is computable by any
   verifier, and `h` is exactly the set of coefficients where
   `HighBits(w') != w1`. An MPC check therefore cannot keep the hints from the
   transcript; `P2` only conditions which attempts are accepted. Removing it
   does not close a channel, it changes the conditioning that the analysed
   construction relies on.
3. We could not re-derive, from first principles and within this note, that
   `P1` alone preserves that analysis. `P2` is inherited from mode3, where
   both conditions are part of the rejection-sampling argument. Removing one
   of them is a change to an analysed construction, and the standing rule is
   that no unproven variant may be enabled.

**Conclusion: dropping `P2` from the MPC path is rejected as unproven.** The
cost finding is real, but a predicate removal is not the fix.

The published resolution. The construction reference already cited in
"References" develops exactly this incompatibility and resolves it at the
root: it distributes the secret as **short replicated shares**, which lets
each party perform **rejection sampling locally on its own response share**, so
neither a global abort MPC nor a global norm circuit is needed. The published
claims are: valid FIPS 204 signatures; up to six parties and any threshold;
dishonest-majority active security (up to `T - 1` corruptions); per-party
communication below 1 MB and signing latency under 20 ms locally and under 1 s
over a WAN. Its "short partial secret per party for each session" premise is
already satisfied here: the CNF-RSS components are `+/-1`, so one active
signer's five assigned components form a short share of the aggregate secret.

What this means for this note:

- The global `P1` and `P2` MPC circuits ("Distributed Norm Checks") exist
  because the nonce section insists on `y` uniform on `S` and a global
  accepted interval. That choice is what forces a shared carry, two-sided
  comparisons over 1280 and 1536 coefficients, and about `3e9` shared
  multiplications per accepted signature.
- The reviewed construction replaces it with per-party local rejection on
  short nonce shares, an accepted-set argument over per-party bounds, and the
  canonical public hint derivation this note already specifies. The carry
  obligation disappears with the uniform-on-`S` requirement.
- Everything else survives unchanged: single-use records, the public/hidden
  boundary and its corollaries, strict canonical encodings, the journal and
  burn rules, and the acceptance criteria. (R57 note: MAC-authenticated
  openings did *not* survive, because the revised construction has no
  shared-secret arithmetic to authenticate.)

Planned revision, to be authorized before any code or spec change lands:

1. Obtain and review the full construction paper and its supplementary
   material: distribution analysis, per-party bounds, hint handling, active
   security argument, and parameter tables.
2. Re-derive per-party nonce radii, the accepted aggregate bound, the expected
   attempts per signature, and the hint weight for this note's parameters, and
   confirm `||z||inf < Gamma1 - Beta` and the two public hint checks hold by
   construction.
3. Replace "Nonce Generation, Reduction, and the Carry Obligation" and
   "Distributed Norm Checks" with the reviewed construction, keep the R53
   correction's honesty about attempt counts, and re-pin the cost envelope by
   test.
4. Re-verify against the unmodified verifier with the same fifteen-subset
   interop test, then resume the executor implementation slices.

Status: the revision this section anticipated has landed as R57. `P2` as a
global MPC predicate is removed together with the rest of the distributed norm
circuits; its conditioning role is carried by the per-party rejection and by
the public `||delta||inf <= Gamma2` combine check, exactly as in the reviewed
construction. The R55 finding stands as the reason the *predicate* was not
simply dropped from an unchanged design.

### Reviewed inputs (R56)

Step 1 of the revision reviewed the available material: the preview writeup,
the workshop slides, the conference poster, the full-version mirror of the
construction paper, and a public reimplementation used to cross-check the
parameter tables. What the sources establish:

- The secret is shared over subsets of size `N - T + 1` drawn independently
  from `[-Eta, Eta]`. For six parties and threshold four that is `C(6,3) = 20`
  three-member subsets, exactly the CNF-RSS topology here, so one active
  signer's own share is short with infinity norm at most `5*Eta`.
- A signer evaluates and rejects its own partial response locally, and the
  aggregate is published only when every signer accepted. The aggregate
  opening is the plain sum: the per-party rejection lemma is what makes the
  accepted partial response distribution independent of the secret, so no
  extra mask is needed.
- Combination performs only size and compatibility checks: the aggregate
  response norm against `Gamma1 - Beta`, the difference between the
  approximate and final commitment against `Gamma2`, and the hint weight
  against `Omega`, then it packs and verifies end to end. The sources describe
  the second mode3 predicate as existing only for size compatibility, so the
  per-party judgement replaces both global predicates.
- Remaining multi-party online work: the round-1 commitments, the aggregate
  openings of the commitment and the response, the rounding that produces
  `w1`, the hints, the parallel attempts, and the final pack-and-verify.
- Security skeleton: game-based threshold unforgeability in the ROM against
  static corruption of up to `T - 1` parties, reduced to MLWE and to
  single-party ML-DSA unforgeability. Adaptive security and robust or
  identifiable abort are not claimed.

Three items must be read from the full paper before the section rewrite,
because the reviewed copies were truncated or indirect:

1. Whether the round-2 value a signer publishes is the full commitment `A*r`
   or only its rounded high part. Corollary 1 makes that difference fatal, so
   the rewrite must follow the paper exactly.
2. The hyperball parameters and parallel-slot count for the mode3 parameter
   set at `(T, N) = (4, 6)`, which the truncated copy did not include.
3. Whether the CNF-RSS component bound should return to `Eta = 4`, as the
   reviewed construction uses, or stay at the R49 value `+/-1`. The choice
   interacts with the MLWE re-estimation and with the per-party rejection
   distribution.

### Revision Record (R57)

The three R56 reads were completed against the full sources (the NIST preview
writeup, the MPTS 2026 slides, the full eprint version, and the public
implementation), with these verbatim findings:

1. **What round 2 publishes.** The protocol reveals the full commitment shares:
   "Second round: parties reveal the values of `(w_i)_{i in act}`", and each
   share is a full MLWE sample: "each party uses a full MLWE sample as
   commitment `w_i` (i.e. `w_i = A*y + e`) instead of using `A*y` as in
   ML-DSA. This change allows for direct reveal of `w_i` before rounding, even
   in case of rejection of the partial signatures." Only the challenge hash
   uses the high bits: `c_tilde = H(mu || HighBits(w, 2*gamma2))` with
   `w = sum_i w_i`. Corollary 1 explains why the error term is what makes this
   possible, and this note adopts the reveal exactly as published.
2. **The hyperball parameters and the parallel-slot count.** Table 2 defines
   the slot count (the paper's `K`, this note's `J`), `nu` as the expansion of
   the first `L` coordinates, `r`/`r'` as the target and sampling radii, and
   `M = (r'/r)^(N*(K+L))`; `HRej` (Fig. 4) fixes the test
   `z := (v^(1)/nu, v^(2)) + r; reject if ||z|| > r` and returns
   `round(z^(1)*nu, z^(2))`. For mode3 at `(T, N) = (4, 6)` the published row
   is `r = 488704`, `r' = 488969`, `J = 804`, with `nu = 6` for the whole
   ML-DSA-65 parameter set. The per-party acceptance exponents published for
   all five `(T, 6)` rows are reproduced by `p = M^(-T)`.
3. **The per-party criterion.** The screening is the ball rejection above; the
   implementation's "Excess" form is that same test with the first `L` blocks
   divided by `nu^2` before the squared norm. The per-party shift bound is
   defined by "for any `m_i` returned by `RSSRecover` and
   `(u1, u2) = sum_{I in m_i} s_I`, `||(1/nu * c*u1, c*u2)||_2 <= B` with
   overwhelming probability", and the paper's own script computes it as
   `B = 1.3 * sqrt((K + L/nu^2) * N * ceil(C(N,T-1)/T)) * sigma_eta * sqrt(Tau)`.
   The correctness assertion in its reduction is
   `||(1/nu * c*spart_i^(1), c*spart_i^(2))||_2 <= B` for every signing party
   and slot.

Decisions taken with those inputs:

- The construction is adopted as published, with the reveal of the full `w_i`
  and the local rejection; the pre-R57 nonce, carry, and global-norm machinery
  is retired from the signing path.
- The component bound stays `+/-1` (R49). The reference's `RSS` sampler is used
  with `eta = 1`, which shrinks `B` from `2082.79` to `658.64` and the radii
  correspondingly; the deviation from the published `eta = 4` is deliberate
  and is recorded in "Component Bound Decision (R57)".
- `expo` and `nu` are re-searched for our parameters with the reference's own
  search procedure, landing at `expo = 3.3`, `nu = 6`, `J = 11`, which is far
  more efficient than the published `(4,6)` row (`J = 804`) because of the
  smaller `B`.
- The construction's analysis is inherited as stated there: game-based
  threshold unforgeability in the ROM against static corruption of up to
  `T - 1` parties, reduced to Module-LWE and to single-party ML-DSA
  unforgeability, with no adaptive security and no robustness claimed. This
  note does not re-prove it, and the lattice-norm gap of our aggregate secret
  remains the recorded open estimate.
- The round-2 reveal, the acceptance bit, and the accepted response parts are
  added to the public boundary; Corollaries 1-5 are rewritten to explain what
  forces the error term, the single-use rule, and the local rejection.
- Verification of the revision: the derivation reproduces the published
  `(4,6)` mode3 radii and slot count (parameter section), and the reference
  driver is re-based on the revised construction in R58 with the same
  fifteen-subset interop test.

### External references consulted (R55)

- Celi, Delerue, del Pino, Espitau, Niot, Prest, "Efficient Threshold ML-DSA
  from Short Secret Sharing" (Mithril), NIST Multi-Party Threshold Cryptography
  Call preview writeup, 2026-01-19:
  https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Mithril-PW01.pdf
- The same team's MPTS 2026 slides, which state the distributed flow (per-party
  short nonce share, per-party rejection, aggregate accepted only if all
  accept) and the short-share requirement:
  https://csrc.nist.gov/csrc/media/presentations/2026/mpts2026-3b7/images-media/mpts2026-3b7-slides-mithril-mldsa-niot.pdf
- "Poster: Efficient Threshold ML-DSA up to 6 Parties", ACM CCS 2025, which
  states the per-party rejection sampling, hyperball rejection, FIPS 204
  compatibility, and the per-party communication bound:
  https://dl.acm.org/doi/10.1145/3719027.3760739
- The paper record this note's reference list cites as the construction
  reference: https://inria.hal.science/hal-05442192v1

## Hints From the Public Verification Equation

The hint `h` is derived without `t0` and without MPC, and in the revised
construction it is a function of public values only.

`w' = A*z^(1) - c*t1*2^D` is fully computable from public values: `A` from
`rho`, `z^(1)` and `c` from the transcript being assembled, and `t1` from the
public key. `w = sum_i w_i` is public after round 2. Therefore
`delta = w - w'` is public, the hint bit at each coefficient is simply "the two
high parts differ" via `MakeHint(delta, w')`, and `h` is assembled in the clear
after the responses are aggregated.

Three mandatory public checks follow, all on public values:

1. `||z^(1)||inf < Gamma1 - Beta` (native `Beta = 196`);
2. `||delta||inf <= Gamma2`, the precondition that makes the hint well defined;
3. the Hamming weight of `h` is at most `Omega = 55`.

The packed signature is additionally verified end to end through
`AssembleVerifiedMode3Signature`, which re-checks the first and third
conditions independently.

This preserves the standing decision that `t0` is never stored, shared, or
reconstructed by the threshold backend.

## Rounds, Messages, and State Machine (R57)

The state names are the ones already used by the plan and the single-use design:
`Created -> Prepared -> Committed -> Challenged -> Responded -> Finalized`, with
transitions to `Burned`. `Challenged` is the wallet-level view of the round-2
opening; the single-use journal does not distinguish it because nothing durable
changes between the commitment and the response. In the revised construction a
*signing request* owns `J` parallel slots, and each slot is one attempt with its
own committed randomness and its own slot-bound digest; the first slot that
every signer accepted and that passes the public checks becomes the signature.

**Round 0 - session.** The signing session identifier is
`Dilithium3SigningSessionID(request, signerIDs)` exactly as implemented in
`sign_session.go`: domain `QAU-TDILITHIUM3-V1-SIGNING-SET`, the base attempt
identifier, and the strictly ascending signer positions. All four signers must
accept the identical session identifier, protocol, key generation, committee
digest, epoch, slot, domain, and message digest before round 1. Each parallel
slot is additionally bound by its slot index, so a coordinator can never permute
or mix slot transcripts.

**Round 1 - commit.** Each signer samples `(x1_i, x2_i)` uniformly in
`B_{L+K}(r')`, computes `w_i = [A I]*(nu*x1_i, x2_i)`, and publishes a binding
commitment to `(slot, w_i)`. Commitment must precede every reveal, otherwise a
rushing signer could adapt its randomness after seeing the others and bias
`w1`. The reference driver drives all four signers in one process and folds the
four commitments into one digest; the networked executor must attribute each
commitment to its own signer.

**Round 2 - reveal and challenge.** Every signer reveals `w_i`; anyone computes
`w = sum_i w_i`, `w1 = HighBits(w)`, `c_tilde = SHAKE256(mu ||
EncodeHighBits(w1))[0:32]`, and `c = DeriveMode3Challenge(c_tilde)`. `c` is a
function of the public reveal, exactly as in native mode3, and it is fixed
before any response exists; it is not an independent random oracle draw.

**Round 3 - respond, reject locally, aggregate.** Each signer computes its
challenge shift `v_i = c*spart_i` and applies its own rejection test from the
previous section. Each signer publishes its acceptance bit; for a slot that
every signer accepted, each signer then publishes
`z_i^(1) = v_i^(1) + round(nu*x1_i)`, and the aggregate
`z^(1) = sum_i z_i^(1)` is public. On a rejected slot nothing else is
published, the slot is burned, and a reason code is recorded. Per Corollary 3,
no response of a rejected slot ever leaves a signer.

**Round 4 - finalize.** Compute `w' = A*z^(1) - 2^D*c*t1`,
`delta = w - w'`, and `h = MakeHint(delta, w')` publicly; run the three public
checks; assemble the 3293-byte signature through
`AssembleVerifiedMode3Signature`; and finalize the journal record. A failed
check aborts only that slot.

## Malicious Coordinator and Two Corrupt Participants

The coordinator routes messages and may reorder, drop, duplicate, replay, or
forge them. It is not trusted with any secret. The adversary additionally
controls up to two of the six committee members.

Direct consequences that the implementation must satisfy:

- the honest four-signer set must not need the coordinator to hold any share,
  any `w_i` before its designated reveal, any response part, or any raw
  randomness;
- two corrupt signers must not be able to determine `w1` before committing, to
  force a specific `c`, to learn any honest `(x1_i, x2_i)` or `spart_i`, or to
  make an honest signer release a response for a slot it rejected;
- a corrupt signer can always abort, because no robustness is claimed, but its
  deviations must be attributable: a conflicting round-1 commitment, an
  inconsistent reveal, a response inconsistent with the committed randomness,
  and a silence are separate reason codes with the responsible position;
- a corrupt signer that aborts after round 1 must be recoverable by a fresh
  slot with fresh randomness for every signer, and no transcript of the aborted
  slot may be reused;
- the coordinator's complete view across rejected and accepted slots must not
  permit the Corollary 3 reconstruction: this is why a rejected slot publishes
  nothing, why responses are released only for slots every signer accepted, and
  why the randomness is single-use.

## Abort, Rejection, Burn, and Evidence

- A local rejection is a normal protocol outcome. It burns the slot and opens
  no secret-derived value: the acceptance bit is published and nothing else.
- A burned slot must be recorded in the signing journal so that its randomness,
  group assignment, and session identifier can never be reused. This is the
  existing single-use rule; the signing journal already turns every
  non-finalized record into `SingleUseBurned` on restart.
- Evidence for a complaint is limited to the disputed transcript fields, the
  sender's identity signature, and digest-level accusations. Evidence must never
  contain a coefficient of the raw randomness, of either half of `z_i`, of
  `spart_i`, or of the secret.
- A missing or conflicting round-1 commitment, an inconsistent reveal, a
  response inconsistent with the committed randomness, and a silence are all
  attributable and are recorded with the responsible participant position.
- A public combine check failure in round 4 is a public abort of that slot: it
  needs no evidence beyond the transcript the combiner already holds.

## Open Obligations Before the Backend Can Be Enabled

These are engineering and cryptographic-derivation tasks on our side. They are
listed so that no part of the backend is switched on with an unmet premise.
Production enablement itself remains an operator decision, as already stated in
the threshold design document.

1. **Networked executor and sampler.** R51 (`ca3559f`) fixed the executor
   contract and the single-use lifecycle, and both are reused. The R52
   in-process arithmetic is retired from the signing path. What remains before
   enablement: the four round message kinds with canonical encodings, the
   inbox authorization, evidence and reason codes, slot batching, and the
   uniform-ball sampler with a distribution test and its placement inside the
   signer process. No production path may depend on the in-process reference
   driver.
2. ~~Nonce distribution proof.~~ **Resolved by R57**: the randomness
   distribution is the reviewed construction's `chi_r` with the pinned
   parameters, and the per-party rejection lemma supplies the shift
   independence. Its replacement is the sampler-validation obligation in item 1
   plus the parameter caveats recorded in the parameter section.
3. ~~Aggregate secret distribution and parameter rederivation.~~ **Decided
   (R57)**: the component bound stays `+/-1`, the parameter table is pinned, and
   the residual is the lattice security re-estimation in item 6.
4. ~~Sampler code change.~~ **Resolved** by R49-MPC-PARAMS (`274e4f7`): the
   component bound is `RSSComponentEta = 1` and the DKG component tests use the
   new bound. Existing experimental share records are invalidated, not migrated.
5. **Constant-time and side-channel review** of the sampler, the rounding, the
   rejection test, the response computation, and the remaining comparison
   paths, including the requirement that no branch or memory access depends on
   a secret coefficient. The ball sampler is the new item on this list.
6. **Lattice security re-estimation** for the aggregate secret distribution, as
   specified in the preceding section. No numeric security claim may be
   published before this is done.
7. **Removal of the insecure path from production reach.**
   `sign_combine_test.go` and `sign_combine_probe_test.go` must remain test-only
   and must be provably unreachable from any production package.
8. **Disposition of the retired pre-R57 machinery.** `mpc_arithmetic.go`, the
   executor contract's secret-handle interfaces, and the `BetaEffective`,
   `NormBoundZ`, and `NormBoundR0` constants are off the signing path after
   R58. R58 deletes what is unused; anything kept must be test-only or
   explicitly quarantined, and nothing on the signing path may import it.

## Test Strategy and Acceptance Criteria

Vector and unit level, against the local reference implementation:

- the ball sampler passes a distribution test for uniformity in the ball and
  for the rounding convention, and its output feeds the rejection test
  bit-exactly (the sampler is part of the side-channel review);
- the rejection test matches a direct real-arithmetic evaluation of
  `||(v^(1)/nu + x1, v^(2) + x2)|| <= r` over boundary radii, including points
  on the sphere;
- in-the-clear `HighBits` evaluation against `decomposeCoefficient` over
  boundary, wrap, and `Q - 1` cases (the tests built for the retired circuit);
- hint assembly checked against `UseHint` and the weight bound;
- `delta` and the three public checks evaluated against direct computation on
  generated vectors, including the exact boundary values.

Protocol level:

- all 15 four-member subsets of the six-member committee each produce one
  3293-byte signature accepted by the unmodified `mode3.Verify`;
- no three-share subset can produce an accepted signature;
- no message, journal record, coordinator view, or evidence object contains a
  complete `s1`, `s2`, `t0`, any raw `(x1_i, x2_i)`, any `z_i^(2)`, or the
  complete private-key encoding;
- a rejected slot publishes no response, and no rejected value ever reaches a
  signature or the transcript;
- abort and burn behaviour under an injected corrupt signer and an injected
  malicious coordinator, including the invariant that a slot's randomness is
  never reused.

Operational level, in the development network only, behind the existing
default-off gates: repeated and interleaved requests against the running
committee, confirming that randomness and group assignments are never reused,
that the `J`-slot schedule reaches the expected per-request success rate, and
that a restart resumes a journaled attempt rather than starting a conflicting
one.

## Delivery Order

1. This note. *(R57 revision landed; everything before "Revision Record (R57)"
   is kept as history)*
2. Component sampler change (`rss_sampler.go` to the `+/-1` bound). *(landed,
   R49-MPC-PARAMS)*
3. Reference driver on the revised construction: per-signer ball randomness,
   the MLWE commitment reveal, the local rejection test, the aggregate
   response, and the public combine. Status: R53 implemented the pre-R57
   construction inside the signing state machine; R58 rewrites the arithmetic
   inside the same state machine, re-verifies the fifteen subsets, and re-pins
   the cost test.
4. Lattice security re-estimation for the aggregate secret distribution
   (obligation 6). Independent of 3 and can run in parallel.
5. The four-of-six signing state machine and message encoding, producing the
   3293-byte signature. Status: the wallet-side reference driver and the state
   machine landed in R53 and are re-based in R58; the exported
   `StartSigning`/`HandleSigningMessage` entry points and the real `J`-slot
   rejection loop wait on the networked executor of obligation 1.
6. Node wiring for finality and sealing, leaving the mainnet default unchanged
   and not weakening any fallback rule.

## References

- `2026-09-24-qau-dilithium3-v1-cnf-rss-design.md` — sharing topology, DKG,
  component allocation, and the signing consequences this note extends.
- `2026-09-24-qau-threshold-dilithium3-v1-design.md` — security profile and
  compatibility decision.
- `2026-09-26-qau-dilithium3-v1-dkg-session-derivation.md` — how a running node
  derives its DKG session from chain state.
- `2026-09-27-qau-dilithium3-v1-signing-executor.md` — the interactive executor
  layer; its cost finding is what R57 resolves.
- `wallet/tss/protocol/dilithium3v1/rounding.go` — local mode3 rounding
  reference for `Decompose`, `HighBits`, `LowBits`, `MakeHint`, `UseHint`.
- CRYSTALS-Dilithium specification, round 3, parameter set Dilithium3.
- Celi, Delerue, del Pino, Espitau, Niot, Prest, "Efficient Threshold ML-DSA
  for Groups of up to 6 Signers", USENIX Security 2026 / NIST PQC Conference
  2025, eprint 2026/013 — construction reference. The parameter cross-checks
  used the paper's own `params/hyperball.sage` procedure and its public
  implementation (`Threshold-ML-DSA`); see "Revision Record (R57)".
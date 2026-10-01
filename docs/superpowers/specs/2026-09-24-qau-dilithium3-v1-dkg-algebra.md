# QAU Threshold Dilithium3 v1 DKG Algebra Gate

**Status:** Review gate closed against BLS12-381 scalar-field reuse; superseded by the approved CNF-RSS design

**Date:** 2026-09-24

## Scope

This note freezes the arithmetic requirements for dealerless sharing of the
legacy CIRCL Dilithium mode3 secret vectors. It does not define a production
commitment scheme. Its immediate purpose is to prevent the existing BLS12-381
Pedersen/Feldman implementation from being reused under incompatible field
arithmetic.

## Dilithium Share Domain

In the rejected Shamir design, each `s1`, `s2`, and `t0` coefficient would have
been an element of `F_q`, where `q = 8380417`, and a four-of-six sharing would
have used degree-three polynomials over exactly `F_q`. Addition,
multiplication, evaluation, interpolation, refresh, and reconstruction would
all have reduced modulo `q`. The approved CNF-RSS design does not use these
Shamir polynomials, but the incompatibility argument below remains a permanent
regression guard against reintroducing them with the wrong commitment field.

The canonical wire representation of a coefficient is the unique integer in
`[0, q)`. A commitment verifier must bind that canonical value and must verify
the same polynomial equation over `F_q`.

## Required Verification Equation

For a dealer polynomial `f(X) = sum(a_j X^j)` and recipient coordinate `x`, a
verifier must accept a private value `y` only when `y = f(x) mod q`. If hiding
blinds are used, the blind polynomial must use arithmetic compatible with the
commitment relation and must not change the `F_q` equality being proved.

The construction must additionally prove that every committed coefficient and
opened value has one canonical `F_q` interpretation. Parsing an integer and
reducing it after verification is insufficient because it permits distinct
commitment-domain values to represent one Dilithium coefficient.

## Why the Existing BLS12-381 Pedersen VSS Is Incompatible

The existing implementation commits with exponents in the BLS12-381 scalar
field `F_r`, whose modulus is not `q`. The direct integer embedding
`i: F_q -> F_r` is injective for canonical single coefficients, but it is not a
field homomorphism.

For example, in `F_q`:

```text
(q - 1) + 1 = 0 mod q
```

Under the direct embedding into `F_r`:

```text
i(q - 1) + i(1) = q != 0 mod r
```

Therefore exponent addition in the BLS12-381 commitment group verifies an
`F_r` polynomial relation, not the required `F_q` relation. Reducing an opened
share modulo `q` after the group equation does not repair this mismatch.
Interpolation, refresh, and maliciously chosen wraparound values produce the
same problem.

Using a prime-order group of order `q` is also unacceptable: `q` is only about
23 bits, so its discrete logarithm problem has negligible security. A secure
replacement must not obtain compatibility by choosing a cryptographically tiny
commitment group.

## Range and Complaint Requirements

A replacement construction must provide all of the following before code is
enabled:

1. Binding to one canonical coefficient in `[0, q)`.
2. Hiding of every dealer coefficient and every honest recipient share.
3. Verification of degree-three evaluation over `F_q`.
4. Complaint evidence limited to the disputed dealer-recipient-coordinate
   tuple and unable to reveal unrelated shares.
5. Domain separation by protocol, DKG session, dealer, recipient, vector,
   polynomial index, and coefficient index.
6. A proof or reduction for binding, hiding, and sound complaint adjudication.

## Decision

The BLS12-381 Pedersen/Feldman implementation remains legacy-only and must not
be imported by `wallet/tss/protocol/dilithium3v1`.

The approved replacement avoids cross-field homomorphic commitments entirely.
It uses the fixed four-of-six CNF replicated-sharing topology defined in
`2026-09-24-qau-dilithium3-v1-cnf-rss-design.md`. Three members replicate each
component, verify its derived partial public contribution, and publish that
contribution for final public-key assembly. The Dilithium3 v1 backend remains
behind both experimental gates until that design passes its implementation and
review requirements.

## References

- CRYSTALS-Dilithium specification, round 3, parameter set Dilithium3.
- Torben Pryds Pedersen, "Non-Interactive and Information-Theoretic Secure
  Verifiable Secret Sharing," CRYPTO 1991.
- Paul Feldman, "A Practical Scheme for Non-interactive Verifiable Secret
  Sharing," FOCS 1987.

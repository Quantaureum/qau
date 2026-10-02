// Quantaureum Node source, version 1.0.0.
// Package vdf implements the post-quantum verifiable delay function used to
// harden the consensus randomness beacon against last-revealer bias.
//
// The construction follows Papercraft (Osadnik, Kaviani, Cini, Lai, Malavolta;
// IEEE S&P 2025, IACR ePrint 2025/879): sequential evaluation of iterated
// Ajtai hashing over a cyclotomic ring, with a lattice succinct argument
// certifying exact sequentiality. This package currently provides the
// arithmetic core (cyclotomic ring + prime-field helpers). The sequential
// evaluation loop and the proof system are added in subsequent milestones.
//
// Parameters (fixed at genesis; see docs for the selection rationale):
//
//	Ring:   Z_q[x]/(Φ_24(x)) where Φ_24(x) = x^8 - x^4 + 1
//	Degree: 8 (ring elements carry 8 coefficients)
//	Secret: none — everything in this package is public-key-free arithmetic.
package vdf

// Phi is the number of coefficients per ring element, equal to φ(24) = 8.
const Phi = 8

// Conductor is the cyclotomic conductor: x^Conductor ≡ 1 in the ring because
// x^12 ≡ -1 mod Φ_24(x).
const Conductor = 24

// QBC is the prime modulus used by the Papercraft B/C parameter families
// (q - 1 = 2^18 · 17,592,186,044,363). It is the default modulus for this
// package because the reference benchmarks (reports A/B/C) and our local
// calibration runs use it.
const QBC uint64 = 4611686019232694273

// QA is the prime modulus used by the Papercraft A parameter family
// (q - 1 = 2^33 · 5,368,709,19, giving NTT-friendly 2-adicity 33).
// Kept for completeness; not the default.
const QA uint64 = 4611686078556930049

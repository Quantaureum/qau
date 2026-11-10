// Quantaureum Node source, version 1.0.0.
package qzkp

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/pedersen"
)

// TestTxValueInRange_Binding exercises the circuit-bound range proof end to
// end with a single compiled circuit (the emulated BLS12-381 G1 circuit is
// expensive to compile; all cases share one SigmaProtocol cache).
//
// The binding statement proven is: C_tx == value*G + blinding*H AND
// value < 2^bitLength, with C_tx a public circuit input. The negative cases
// assert that the proof is only valid for the exact commitment it was
// generated for (audit run-8 root fix).
func TestTxValueInRange_Binding(t *testing.T) {
	sp := testProtocol(t)
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("pedersen generator: %v", err)
	}

	value := big.NewInt(1000)
	blinding, err := crand.Int(crand.Reader, pedersen.CurveOrder())
	if err != nil {
		t.Fatalf("rand blinding: %v", err)
	}
	commitment := gen.Commit(value, blinding).Bytes()

	proof, err := sp.ProveTxValueInRange(value, blinding, 128, commitment, gen)
	if err != nil {
		t.Fatalf("ProveTxValueInRange: %v", err)
	}
	if proof == nil {
		t.Fatal("proof should not be nil")
	}
	if len(proof.TxCommitment) != G1PointSize {
		t.Fatalf("bound commitment length %d, expected %d", len(proof.TxCommitment), G1PointSize)
	}
	if !bytes.Equal(proof.TxCommitment, commitment) {
		t.Fatal("bound commitment must byte-match the transaction commitment")
	}

	// Positive case: verifying against the SAME commitment passes.
	if err := sp.VerifyTxValueInRange(proof, commitment); err != nil {
		t.Fatalf("VerifyTxValueInRange (same commitment): %v", err)
	}

	// Negative case (replay): the exact same proof bytes verified against a
	// DIFFERENT commitment (different amount, same blinding) must be
	// rejected — a proof cannot be transplanted onto another transaction.
	otherCommitment := gen.Commit(big.NewInt(999), blinding).Bytes()
	if err := sp.VerifyTxValueInRange(proof, otherCommitment); !errors.Is(err, ErrTxCommitmentMismatch) {
		t.Fatalf("replay onto different commitment: expected ErrTxCommitmentMismatch, got %v", err)
	}

	// Negative case (tampering): flipping one byte of the bound commitment
	// must be rejected before any cryptographic work.
	tampered := &TxRangeProof{
		ProofBytes:   proof.ProofBytes,
		TxCommitment: append([]byte(nil), proof.TxCommitment...),
		BitLength:    proof.BitLength,
	}
	tampered.TxCommitment[10] ^= 0x01
	if err := sp.VerifyTxValueInRange(tampered, commitment); err == nil {
		t.Fatal("tampered bound commitment must be rejected")
	}

	// Negative case: verifying against a commitment of the wrong length must
	// be rejected (fail-closed, not silently skipped).
	if err := sp.VerifyTxValueInRange(proof, []byte("short")); err == nil {
		t.Fatal("short verifier commitment must be rejected")
	}

	// Zero amount edge case: the circuit uses complete arithmetic, so the
	// degenerate witness (value = 0) must prove and verify.
	zeroBlinding, err := crand.Int(crand.Reader, pedersen.CurveOrder())
	if err != nil {
		t.Fatalf("rand blinding: %v", err)
	}
	zeroCommitment := gen.Commit(big.NewInt(0), zeroBlinding).Bytes()
	zeroProof, err := sp.ProveTxValueInRange(big.NewInt(0), zeroBlinding, 128, zeroCommitment, gen)
	if err != nil {
		t.Fatalf("ProveTxValueInRange (zero amount): %v", err)
	}
	if err := sp.VerifyTxValueInRange(zeroProof, zeroCommitment); err != nil {
		t.Fatalf("VerifyTxValueInRange (zero amount): %v", err)
	}

	// Zero blinding edge case: complete arithmetic must also admit the
	// (value, 0) witness (probability ~2^-255 for honest provers, but the
	// constraint system must remain complete).
	zeroBlinding = big.NewInt(0)
	valueOne := big.NewInt(7)
	zeroBlindCommitment := gen.Commit(valueOne, zeroBlinding).Bytes()
	zeroBlindProof, err := sp.ProveTxValueInRange(valueOne, zeroBlinding, 128, zeroBlindCommitment, gen)
	if err != nil {
		t.Fatalf("ProveTxValueInRange (zero blinding): %v", err)
	}
	if err := sp.VerifyTxValueInRange(zeroBlindProof, zeroBlindCommitment); err != nil {
		t.Fatalf("VerifyTxValueInRange (zero blinding): %v", err)
	}
}

// TestTxValueInRange_ProverRejections covers prover-side input validation.
// These paths run before circuit compilation, so no Groth16 setup is needed.
func TestTxValueInRange_ProverRejections(t *testing.T) {
	sp := testProtocol(t)
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("pedersen generator: %v", err)
	}

	blinding, err := crand.Int(crand.Reader, pedersen.CurveOrder())
	if err != nil {
		t.Fatalf("rand blinding: %v", err)
	}

	t.Run("value out of range", func(t *testing.T) {
		tooBig := new(big.Int).Lsh(big.NewInt(1), 128) // == 2^128, not < 2^128
		commitment := gen.Commit(tooBig, blinding).Bytes()
		if _, err := sp.ProveTxValueInRange(tooBig, blinding, 128, commitment, gen); !errors.Is(err, ErrInvalidWitness) {
			t.Fatalf("expected ErrInvalidWitness, got %v", err)
		}
	})

	t.Run("negative value", func(t *testing.T) {
		neg := big.NewInt(-1)
		commitment := gen.Commit(neg, blinding).Bytes()
		if _, err := sp.ProveTxValueInRange(neg, blinding, 128, commitment, gen); !errors.Is(err, ErrInvalidWitness) {
			t.Fatalf("expected ErrInvalidWitness, got %v", err)
		}
	})

	t.Run("commitment mismatch", func(t *testing.T) {
		// The caller passes a commitment that does not match (value,
		// blinding): the prover must refuse instead of binding to a
		// different point.
		value := big.NewInt(500)
		otherCommitment := gen.Commit(big.NewInt(501), blinding).Bytes()
		if _, err := sp.ProveTxValueInRange(value, blinding, 128, otherCommitment, gen); !errors.Is(err, ErrTxCommitmentMismatch) {
			t.Fatalf("expected ErrTxCommitmentMismatch, got %v", err)
		}
	})

	t.Run("invalid bitLength", func(t *testing.T) {
		value := big.NewInt(1)
		commitment := gen.Commit(value, blinding).Bytes()
		if _, err := sp.ProveTxValueInRange(value, blinding, 0, commitment, gen); err == nil {
			t.Fatal("bitLength 0 must be rejected")
		}
		// bitLength >= 255 makes the range constraint vacuous (2^255 exceeds
		// the scalar-field modulus), so it must be rejected on both the
		// prover and the verifier side.
		if _, err := sp.ProveTxValueInRange(value, blinding, 255, commitment, gen); err == nil {
			t.Fatal("bitLength 255 must be rejected (vacuous range)")
		}
		if _, err := sp.ProveTxValueInRange(value, blinding, 257, commitment, gen); err == nil {
			t.Fatal("bitLength 257 must be rejected")
		}
	})

	t.Run("invalid commitment length", func(t *testing.T) {
		if _, err := sp.ProveTxValueInRange(big.NewInt(1), blinding, 128, []byte("nope"), gen); err == nil {
			t.Fatal("short commitment must be rejected")
		}
	})
}

// TestTxRangeProof_MarshalRoundTrip checks the strict serialization format:
// round-trip fidelity and rejection of truncated, legacy-shaped or
// out-of-bounds payloads (no circuit compilation involved).
func TestTxRangeProof_MarshalRoundTrip(t *testing.T) {
	proof := &TxRangeProof{
		ProofBytes:   []byte{0x01, 0x02, 0x03, 0x04},
		TxCommitment: make([]byte, G1PointSize),
		BitLength:    128,
	}
	data, err := proof.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	parsed := &TxRangeProof{}
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(parsed.ProofBytes, proof.ProofBytes) ||
		!bytes.Equal(parsed.TxCommitment, proof.TxCommitment) ||
		parsed.BitLength != proof.BitLength {
		t.Fatal("round-trip mismatch")
	}

	// Missing TxCommitment field entirely (legacy-shaped payload): rejected.
	truncated := data[:4+len(proof.ProofBytes)+4]
	legacy := &TxRangeProof{}
	if err := legacy.UnmarshalBinary(truncated); err == nil {
		t.Fatal("payload without TxCommitment must be rejected")
	}

	// Wrong TxCommitment length (not 48): rejected at marshal time by the
	// structural validation (strict on both ends).
	bad := &TxRangeProof{
		ProofBytes:   proof.ProofBytes,
		TxCommitment: []byte{0xAA, 0xBB},
		BitLength:    128,
	}
	if _, err := bad.MarshalBinary(); err == nil {
		t.Fatal("non-48-byte TxCommitment must be rejected on marshal")
	}

	// Empty proof bytes: rejected on marshal and unmarshal.
	empty := &TxRangeProof{TxCommitment: make([]byte, G1PointSize), BitLength: 128}
	if _, err := empty.MarshalBinary(); err == nil {
		t.Fatal("empty ProofBytes must be rejected on marshal")
	}

	// BitLength out of range: rejected.
	oob := &TxRangeProof{ProofBytes: []byte{0x01}, TxCommitment: make([]byte, G1PointSize), BitLength: 0}
	if _, err := oob.MarshalBinary(); err == nil {
		t.Fatal("BitLength 0 must be rejected on marshal")
	}
}

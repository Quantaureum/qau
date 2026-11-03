// Quantaureum Node source, version 1.0.0.
package consensus

// Regression anchors for the CRND audit findings on the VRF output/input
// handling (QR-26). These tests pin FIXED behavior: if either test fails, a
// CRND fix has been reverted.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// TestPQVRF_CRND10_InputTooLongRejected anchors CRND-10: inputs longer than
// types.HashLength (32 bytes) must be REJECTED, not silently truncated. Both
// entry points are checked — the evaluation path (PQVRFEval, pqvrf.go
// input-length gate) and the verification path (PQVRFVerify). Before the fix
// both copied the input into a fixed 32-byte buffer, so two distinct inputs
// sharing a 32-byte prefix produced identical VRF outputs/verifications.
func TestPQVRF_CRND10_InputTooLongRejected(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	// 33 bytes: exactly one byte over the 32-byte input budget.
	longInput := make([]byte, types.HashLength+1)
	for i := range longInput {
		longInput[i] = byte(i)
	}
	// The 32-byte prefix the pre-CRND-10 code would have silently used.
	prefix := longInput[:types.HashLength]

	_, _, err := PQVRFEval(sk, longInput)
	if !errors.Is(err, ErrPQVRFInputTooLong) {
		t.Fatalf("PQVRFEval(33-byte input) = %v, want ErrPQVRFInputTooLong", err)
	}

	// Verification path: a structurally valid proof/output so the check
	// ordering (proof/output shape first, then input length) reaches the
	// input-length gate.
	proof := &PQVRFProof{Proof: make([]byte, PQVRFProofSize)}
	output := &PQVRFOutput{}
	err = PQVRFVerify(pk, longInput, proof, output)
	if !errors.Is(err, ErrPQVRFInputTooLong) {
		t.Fatalf("PQVRFVerify(33-byte input) = %v, want ErrPQVRFInputTooLong", err)
	}

	// Sanity: the 32-byte prefix itself is still a legal input on both paths.
	if _, _, err := PQVRFEval(sk, prefix); err != nil {
		t.Fatalf("PQVRFEval(32-byte prefix) unexpectedly rejected: %v", err)
	}
}

// TestVRF_CRND03_OutputNotFromPublicData anchors CRND-03: the legacy VRF
// output must be derived from the PROOF (secret-derived material), never from
// public data alone. The pre-fix formula — confirmed from the CRND-03 comment
// on GenerateVRF/computeVRFOutputFromProof in consensus/vrf.go ("Previously,
// the output was SHA3(domain || pubKey || seed)"), with the public git
// history already starting post-fix — was a purely public computation:
//
//	oldOutput = SHA3-256(vrfDomainSeparator || publicKey || seed)
//
// anyone could pre-compute every validator's VRF output, making the whole
// epoch's proposer schedule publicly predictable.
//
// IF THIS TEST FAILS, THE CRND-03 FIX HAS BEEN REVERTED — restore the
// proof-derived output (computeVRFOutputFromProof) before shipping.
func TestVRF_CRND03_OutputNotFromPublicData(t *testing.T) {
	sk, pk := generateTestKeyPair(t)

	var seed types.Hash
	for i := range seed {
		seed[i] = byte(i * 7)
	}

	_, output, err := GenerateVRF(sk, seed)
	if err != nil {
		t.Fatalf("GenerateVRF: %v", err)
	}

	// Reconstruct the documented pre-CRND-03 public formula and require the
	// fixed construction to differ from it.
	h := sha3.New256()
	h.Write(vrfDomainSeparator)
	h.Write(pk.Bytes())
	h.Write(seed[:])
	var oldOutput types.Hash
	h.Sum(oldOutput[:0])

	if bytes.Equal(output.Value[:], oldOutput[:]) {
		t.Fatal("GenerateVRF output equals the pre-CRND-03 public formula " +
			"SHA3(domain||pubKey||seed) — the CRND-03 fix has been reverted")
	}
}

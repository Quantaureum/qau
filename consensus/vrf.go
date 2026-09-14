// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements VRF (Verifiable Random Function) using Dilithium3 signatures.
// Optimized for performance with pre-allocated buffers and batch verification support.
package consensus

import (
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	// VRFProofSize is the size of a VRF proof (Dilithium3 signature)
	VRFProofSize = crypto.Dilithium3SignatureSize

	// VRFOutputSize is the size of VRF output (SHA3-256 hash)
	VRFOutputSize = types.HashLength

	// vrfInputSize is the pre-calculated size of VRF input buffer
	vrfInputSize = 18 + types.HashLength // len("QUANTAUREUM_VRF_V1") + HashLength
)

// MaxVRFVerifyConcurrency limits concurrent goroutines in batch VRF verification.
// audit-fix M-15: prevents goroutine exhaustion from large batch requests.
const MaxVRFVerifyConcurrency = 32

var (
	// ErrInvalidVRFProof is returned when VRF proof verification fails
	ErrInvalidVRFProof = errors.New("invalid VRF proof")

	// ErrInvalidVRFOutput is returned when VRF output doesn't match proof
	ErrInvalidVRFOutput = errors.New("invalid VRF output")

	// ErrNilPrivateKey is returned when private key is nil
	ErrNilPrivateKey = errors.New("private key is nil")

	// ErrNilPublicKey is returned when public key is nil
	ErrNilPublicKey = errors.New("public key is nil")

	// ErrEmptyBatch is returned when batch verification is called with empty slice
	ErrEmptyBatch = errors.New("empty batch for verification")

	// vrfDomainSeparator is used to separate VRF from regular signatures
	vrfDomainSeparator = []byte("QUANTAUREUM_VRF_V1")
)

// ErrInvalidVRFAccumulator is returned when a block header's stored per-epoch
// VRF accumulator does not match the deterministic value recomputed from its
// parent header.
var ErrInvalidVRFAccumulator = errors.New("invalid VRF accumulator")

// ComputeNextVRFAccumulator computes the per-epoch VRF accumulator that a
// child block MUST carry in its header, given its parent's accumulator and
// epoch and the child's own epoch and VRF output.
//
// This is a PURE, deterministic function of the chain (parent header + child
// header) — it does NOT depend on any node-local bookkeeping, restart history,
// sync path, or reorg handling. Every honest node derives the identical value,
// which is what makes proposer election converge.
//
// Semantics (Ethereum-RANDAO-aligned, per-epoch reset):
//   - child in the SAME epoch as parent: parentAcc XOR childVRF
//   - child is the FIRST block of a NEW epoch: childVRF (epoch accumulator resets)
//   - childVRF is zero (genesis / no validator key): parentAcc (unchanged)
//
// The last canonical block of an epoch therefore carries that epoch's FULL
// accumulator, which is what proposer election for epoch+2 reads.
func ComputeNextVRFAccumulator(parentAcc types.Hash, parentEpoch, childEpoch uint64, childVRF types.Hash) types.Hash {
	if childVRF == (types.Hash{}) {
		return parentAcc
	}
	if childEpoch == parentEpoch {
		var acc types.Hash
		for i := 0; i < types.HashLength; i++ {
			acc[i] = parentAcc[i] ^ childVRF[i]
		}
		return acc
	}
	// New epoch: the accumulator resets to this block's VRF output.
	return childVRF
}

// sha3Pool is a sync.Pool for reusing SHA3 hashers.
var sha3Pool = sync.Pool{
	New: func() any {
		return sha3.NewLegacyKeccak256()
	},
}

// VRFProof represents a VRF proof containing the signature
type VRFProof struct {
	Proof []byte // Dilithium3 signature
}

// VRFOutput represents the VRF output value
type VRFOutput struct {
	Value types.Hash // SHA3-256 hash of the proof
}

// VRFVerificationRequest represents a single VRF verification request for batch processing
type VRFVerificationRequest struct {
	PublicKey *crypto.PublicKey
	Seed      types.Hash
	Proof     *VRFProof
	Output    *VRFOutput
}

// VRFVerificationResult represents the result of a VRF verification
type VRFVerificationResult struct {
	Valid bool
	Error error
}

// GenerateVRF generates a VRF proof and output for the given seed.
// The VRF is constructed as:
//   - proof   = Sign(privateKey, domainSeparator || seed)
//   - output  = SHA3-256(domainSeparator || proof || publicKey)
//
// AUDIT (2026) CRND-03: The output is now derived from the PROOF (Dilithium3
// signature) rather than from (publicKey, seed). Previously, the output was
// SHA3(domain || pubKey || seed), which has NO secret input — anyone could
// pre-compute any validator's VRF output, making the entire epoch's proposer
// schedule publicly predictable. The fix derives the output from the proof,
// which can only be produced by the private key holder.
//
// This is safe because Dilithium3's SignTo is deterministic (FIPS 204):
// the signing nonce is derived as r = H(tr || M), making the signature unique
// for (sk, M). Since the proof is deterministic, the output is also unique —
// no grinding is possible. This matches the PQVRF construction already in use
// (see pqvrf.go and pqvrf_security_test.go).
func GenerateVRF(privateKey *crypto.PrivateKey, seed types.Hash) (*VRFProof, *VRFOutput, error) {
	if privateKey == nil {
		return nil, nil, ErrNilPrivateKey
	}

	// audit-fix H-2: Allocate a fresh input buffer instead of using sync.Pool.
	// The buffer is only 50 bytes, so the allocation cost is negligible.
	// Pooling risked use-after-return if Sign retained a reference to the slice.
	input := make([]byte, vrfInputSize)
	copy(input, vrfDomainSeparator)
	copy(input[len(vrfDomainSeparator):], seed[:])

	// Generate proof by signing the input
	proof, err := privateKey.Sign(input)
	if err != nil {
		return nil, nil, err
	}

	pub := privateKey.PublicKey()
	if pub == nil {
		return nil, nil, ErrNilPublicKey
	}

	// AUDIT (2026) CRND-03: Derive output from the proof, not from public
	// data. This makes the output unpredictable without the private key.
	output := computeVRFOutputFromProof(proof, pub.Bytes())

	return &VRFProof{Proof: proof}, &VRFOutput{Value: output}, nil
}

// computeVRFOutputFromProof derives the VRF output from the proof (Dilithium3
// signature) and the public key. Including the public key in the hash prevents
// output collisions between different validators who might produce the same
// signature bytes (astronomically unlikely, but defense-in-depth).
// AUDIT (2026) CRND-03: This replaces computeVRFOutputDeterministic which
// derived the output from (pubKey, seed) — a purely public computation.
func computeVRFOutputFromProof(proof []byte, pubKeyBytes []byte) types.Hash {
	h := sha3.New256()
	h.Write(vrfDomainSeparator)
	h.Write(proof)
	h.Write(pubKeyBytes)
	var out types.Hash
	h.Sum(out[:0])
	return out
}

// VerifyVRF verifies a VRF proof and output against a public key and seed.
// Returns nil if verification succeeds, error otherwise.
//
// AUDIT (2026) CRND-03: The expected output is now recomputed from the
// proof and public key (deterministic given the proof), then compared in
// constant time against the claimed output. Since Dilithium3 SignTo is
// deterministic (FIPS 204), the proof is unique for (sk, input), making the
// output also unique — no grinding is possible.
//
// For batch verification, use VerifyVRFBatch instead.
func VerifyVRF(publicKey *crypto.PublicKey, seed types.Hash, proof *VRFProof, output *VRFOutput) error {
	if publicKey == nil {
		return ErrNilPublicKey
	}
	if proof == nil || len(proof.Proof) != VRFProofSize {
		return ErrInvalidVRFProof
	}
	if output == nil {
		return ErrInvalidVRFOutput
	}

	// audit-fix H-2: fresh allocation (50 bytes) avoids sync.Pool reuse hazard.
	input := make([]byte, vrfInputSize)
	copy(input, vrfDomainSeparator)
	copy(input[len(vrfDomainSeparator):], seed[:])

	// Verify the signature
	valid := publicKey.Verify(input, proof.Proof)
	if !valid {
		return ErrInvalidVRFProof
	}

	// AUDIT (2026) CRND-03: recompute the output from the proof.
	expectedOutput := computeVRFOutputFromProof(proof.Proof, publicKey.Bytes())
	if subtle.ConstantTimeCompare(expectedOutput[:], output.Value[:]) != 1 {
		return ErrInvalidVRFOutput
	}

	return nil
}

// VerifyVRFBatch verifies multiple VRF proofs in parallel.
// Returns a slice of results corresponding to each request.
// This is more efficient than calling VerifyVRF multiple times
// when verifying many proofs.
func VerifyVRFBatch(requests []VRFVerificationRequest) []VRFVerificationResult {
	if len(requests) == 0 {
		return nil
	}

	results := make([]VRFVerificationResult, len(requests))

	// For small batches, verify sequentially
	if len(requests) <= 4 {
		for i, req := range requests {
			err := VerifyVRF(req.PublicKey, req.Seed, req.Proof, req.Output)
			results[i] = VRFVerificationResult{
				Valid: err == nil,
				Error: err,
			}
		}
		return results
	}

	// For larger batches, verify in parallel with bounded concurrency
	// audit-fix M-15: semaphore limits concurrent goroutines to prevent exhaustion
	var wg sync.WaitGroup
	wg.Add(len(requests))
	sem := make(chan struct{}, MaxVRFVerifyConcurrency)

	for i, req := range requests {
		sem <- struct{}{} // Acquire semaphore slot
		go func(idx int, r VRFVerificationRequest) {
			defer func() { <-sem }() // Release semaphore slot
			defer wg.Done()
			// R7-P3 FIX: recover prevents a panic in VerifyVRF from
			// crashing the node. results[idx] stays zero-value (Valid: false).
			defer func() {
				if r := recover(); r != nil {
					qposAdvLogger.Errorf("panic in VRF batch verification worker: %v", r)
				}
			}()
			err := VerifyVRF(r.PublicKey, r.Seed, r.Proof, r.Output)
			results[idx] = VRFVerificationResult{
				Valid: err == nil,
				Error: err,
			}
		}(i, req)
	}

	wg.Wait()
	return results
}

// ComputeVRFOutput is DEPRECATED.
//
// AUDIT (2026) CRND-03: The VRF output is now derived from the proof
// (Dilithium3 signature), not from (publicKey, seed). This is because the
// previous derivation used only public data, making the output predictable.
// Since Dilithium3 SignTo is deterministic (FIPS 204), deriving the output
// from the proof is safe and prevents grinding. Use ComputeVRFOutputFromProof
// instead.
func ComputeVRFOutput(proof *VRFProof) (*VRFOutput, error) {
	return nil, errors.New("ComputeVRFOutput is deprecated; use ComputeVRFOutputFromProof after the CRND-03 VRF fix")
}

// ComputeVRFOutputFromPubKey is DEPRECATED after the CRND-03 fix.
//
// The VRF output can no longer be computed from (publicKey, seed) alone —
// it requires the proof (signature), which can only be produced by the
// private key holder. This makes the output unpredictable without the
// private key. Use GenerateVRF or ComputeVRFOutputFromProof instead.
func ComputeVRFOutputFromPubKey(publicKey *crypto.PublicKey, seed types.Hash) (*VRFOutput, error) {
	return nil, errors.New("ComputeVRFOutputFromPubKey is deprecated after CRND-03 fix; VRF output now requires the proof, use ComputeVRFOutputFromProof instead")
}

// ComputeVRFOutputFromProof computes the VRF output from a proof and public key.
// AUDIT (2026) CRND-03: This replaces the deprecated ComputeVRFOutputFromPubKey.
// The output is SHA3-256(domain || proof || pubKey), which requires the
// private key to produce the proof, making it unpredictable.
func ComputeVRFOutputFromProof(proof *VRFProof, publicKey *crypto.PublicKey) (*VRFOutput, error) {
	if proof == nil || len(proof.Proof) != VRFProofSize {
		return nil, ErrInvalidVRFProof
	}
	if publicKey == nil {
		return nil, ErrNilPublicKey
	}
	return &VRFOutput{Value: computeVRFOutputFromProof(proof.Proof, publicKey.Bytes())}, nil
}

// hashProofOptimized computes Keccak256(proof) using a pooled hasher.
//
// DEPRECATED (audit 2026-06-14, H1): the VRF output is no longer derived from
// the proof bytes. Retained only for backward compatibility with any external
// callers that hash proofs directly; not used by the VRF itself anymore.
//
// QUANTUM-R7-09 (audit 2026-07-17, Low): use comma-ok type assertion to avoid
// panic if the pool is ever polluted with an unexpected type. Fail open by
// constructing a fresh hasher; do not return the bad object to the pool.
func hashProofOptimized(proof []byte) types.Hash {
	rawHasher := sha3Pool.Get()
	hasher, ok := rawHasher.(interface {
		Reset()
		Write([]byte) (int, error)
		Sum([]byte) []byte
	})
	if ok {
		defer sha3Pool.Put(hasher)
	} else {
		hasher = sha3.NewLegacyKeccak256()
	}
	hasher.Reset()
	hasher.Write(proof)
	var out types.Hash
	copy(out[:], hasher.Sum(nil)[:types.HashLength])
	return out
}

// hashProof computes Keccak256 hash of the proof to get VRF output.
// audit-fix R6-2: delegates to hashProofOptimized so both functions use the
// same algorithm (Keccak256). Previously this used sha3.Sum256 (NIST SHA3-256),
// which is a different hash than the Keccak256 used by hashProofOptimized and
// all other consensus hashing (computeShuffleSeed, etc.).
func hashProof(proof []byte) types.Hash {
	return hashProofOptimized(proof)
}

// hashProofOptimized (original implementation) was here; it has been moved up
// and redeclared above with a deprecation note after the H1 VRF fix (the VRF
// output is no longer derived from proof bytes). The detailed security comment
// on sync.Pool hasher reuse still applies to the retained version.

// ProofBytes returns the proof as a byte slice
func (p *VRFProof) ProofBytes() []byte {
	if p == nil {
		return nil
	}
	return p.Proof
}

// OutputBytes returns the output value as a byte slice
func (o *VRFOutput) OutputBytes() []byte {
	if o == nil {
		return nil
	}
	return o.Value[:]
}

// VRFProofFromBytes creates a VRFProof from bytes
func VRFProofFromBytes(b []byte) (*VRFProof, error) {
	if len(b) != VRFProofSize {
		return nil, ErrInvalidVRFProof
	}
	proof := make([]byte, VRFProofSize)
	copy(proof, b)
	return &VRFProof{Proof: proof}, nil
}

// VRFOutputFromBytes creates a VRFOutput from bytes
func VRFOutputFromBytes(b []byte) (*VRFOutput, error) {
	if len(b) != VRFOutputSize {
		return nil, ErrInvalidVRFOutput
	}
	var output VRFOutput
	copy(output.Value[:], b)
	return &output, nil
}

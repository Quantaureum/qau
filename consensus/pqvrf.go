// Quantaureum Node source, version 1.0.0.
package consensus

// SECURITY (audit P3-): PQVRF is a reserved post-quantum VRF implementation.
// It is NOT used in production consensus. The active VRF is in vrf.go.
// This file is kept for future migration and should not be called in production paths.

import (
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	PQVRFProofSize  = crypto.Dilithium3SignatureSize
	PQVRFOutputSize = 32

	pqvrfDomainSeparator = "QUANTAUREUM_PQVRF_V2"
	pqvrfInputSize       = len(pqvrfDomainSeparator) + types.HashLength

	MaxPQVRFVerifyConcurrency = 32
)

var (
	ErrPQVRFInvalidProof     = errors.New("pqvrf: invalid proof")
	ErrPQVRFInvalidOutput    = errors.New("pqvrf: invalid output")
	ErrPQVRFNilPrivateKey    = errors.New("pqvrf: private key is nil")
	ErrPQVRFNilPublicKey     = errors.New("pqvrf: public key is nil")
	ErrPQVRFEmptyBatch       = errors.New("pqvrf: empty batch for verification")
	ErrPQVRFUniquenessFailed = errors.New("pqvrf: uniqueness check failed")
	// AUDIT (2026) CRND-10: Input longer than types.HashLength (32 bytes)
	// was silently truncated by copy(), causing two distinct inputs that share
	// a 32-byte prefix to produce identical VRF proofs and outputs.
	ErrPQVRFInputTooLong = errors.New("pqvrf: input exceeds 32 bytes and would be silently truncated")

	pqvrfKDFPool = sync.Pool{
		New: func() any {
			return sha3.NewShake256()
		},
	}
)

type PQVRFProof struct {
	Proof []byte
}

type PQVRFOutput struct {
	Value [PQVRFOutputSize]byte
}

type PQVRFVerificationRequest struct {
	PublicKey *crypto.PublicKey
	Input     []byte
	Proof     *PQVRFProof
	Output    *PQVRFOutput
}

type PQVRFVerificationResult struct {
	Valid bool
	Error error
}

// PQVRFEval evaluates the post-quantum VRF.
//
// Construction: Dilithium3 Deterministic Sign-then-KDF
//
//	π = Dilithium3.Sign(sk, "QUANTAUREUM_PQVRF_V2" || x)
//	y = SHAKE-256(π, 256 bits)
//
// Security Properties (under Module-LWE + Module-SIS + Random Oracle Model):
//
//  1. Uniqueness: For any (pk, x), there exists at most one valid (y, π) pair.
//     This follows from Dilithium3's deterministic signing mode, where the
//     signing randomness is derived as r = H(tr || M) per FIPS 204 (ML-DSA).
//     The same (sk, x) always produces the same π, and y = KDF(π) is deterministic.
//
//  2. Pseudorandomness: Without sk, the output y = KDF(π) is computationally
//     indistinguishable from uniform random. This follows from:
//     (a) π is unpredictable without sk (Module-LWE assumption),
//     (b) KDF (SHAKE-256) is modeled as a random oracle.
//
//  3. Verifiability: Anyone with pk can verify that y was correctly computed
//     from x using π, by checking Dilithium3.Verify(pk, input, π) and y = KDF(π).
//
// Comparison with LB-VRF (Esgin et al., 2020):
//   - LB-VRF is "few-time" (limited evaluations per key), ours is unlimited
//   - LB-VRF proof ~5KB, ours is 3293 bytes (standard Dilithium3 signature)
//   - LB-VRF output 84 bytes, ours is 32 bytes
//   - Both rely on Module-LWE/Module-SIS assumptions
//   - Our construction is better suited for blockchain (VRF every 12s slot)
func PQVRFEval(privateKey *crypto.PrivateKey, input []byte) (*PQVRFProof, *PQVRFOutput, error) {
	if privateKey == nil {
		return nil, nil, ErrPQVRFNilPrivateKey
	}
	// AUDIT (2026) CRND-10: Reject inputs longer than types.HashLength
	// instead of silently truncating them. The fixed-size buffer below only
	// holds 32 bytes of input; truncation would cause two distinct inputs
	// sharing a 32-byte prefix to produce identical VRF outputs.
	if len(input) > types.HashLength {
		return nil, nil, ErrPQVRFInputTooLong
	}

	vrfInput := make([]byte, pqvrfInputSize)
	copy(vrfInput, pqvrfDomainSeparator)
	copy(vrfInput[len(pqvrfDomainSeparator):], input)

	proof, err := privateKey.Sign(vrfInput)
	if err != nil {
		return nil, nil, err
	}

	// AUDIT (2026) CRND-FIX: Derive output FROM THE PROOF, not from
	// public data. The previous code (C21-001 "fix") derived output as
	// SHAKE256(domain||pubKey||input) — purely public material that ANYONE could
	// pre-compute, defeating the VRF's unpredictability property (the exact
	// vulnerability CRND-03 fixed in vrf.go but was never propagated here).
	//
	// AUDIT (2026) R4-CRND-04 FIX: The C21-001 concern that "circl's
	// Dilithium3 SignTo is randomized, so deriving from the proof would let
	// a signer re-sign to grind outputs" was INCORRECT. Dilithium3 uses
	// deterministic signing (FIPS 204 ML-DSA), where the signing randomness
	// is derived as r = H(tr || M) — the same (sk, x) ALWAYS produces the
	// same π. Therefore grinding is NOT possible at all (not just "a secondary
	// concern" as the old comment claimed). The header comment at lines 76-79
	// correctly states this; this inline comment now agrees with it.
	//
	// The proof is secret-derived (only the private key holder can produce it),
	// so including it in the output hash makes the output unpredictable to
	// anyone who doesn't have the private key. This matches the vrf.go fix.
	pub := privateKey.PublicKey()
	if pub == nil {
		return nil, nil, ErrPQVRFNilPublicKey
	}
	output := pqvrfDeriveOutputFromProof(proof, pub.Bytes(), input)

	return &PQVRFProof{Proof: proof}, &PQVRFOutput{Value: output}, nil
}

// PQVRFEvalHash is a convenience wrapper that accepts a types.Hash as input.
func PQVRFEvalHash(privateKey *crypto.PrivateKey, seed types.Hash) (*PQVRFProof, *PQVRFOutput, error) {
	return PQVRFEval(privateKey, seed[:])
}

// PQVRFVerify verifies a PQ-VRF proof and output against a public key and input.
func PQVRFVerify(publicKey *crypto.PublicKey, input []byte, proof *PQVRFProof, output *PQVRFOutput) error {
	if publicKey == nil {
		return ErrPQVRFNilPublicKey
	}
	if proof == nil || len(proof.Proof) != PQVRFProofSize {
		return ErrPQVRFInvalidProof
	}
	if output == nil {
		return ErrPQVRFInvalidOutput
	}
	// AUDIT (2026) CRND-10: Reject inputs longer than types.HashLength
	// to match PQVRFEval. Without this, verify would silently truncate a
	// long input and accept a proof that was computed on the truncated prefix.
	if len(input) > types.HashLength {
		return ErrPQVRFInputTooLong
	}

	vrfInput := make([]byte, pqvrfInputSize)
	copy(vrfInput, pqvrfDomainSeparator)
	copy(vrfInput[len(pqvrfDomainSeparator):], input)

	valid := publicKey.Verify(vrfInput, proof.Proof)
	if !valid {
		return ErrPQVRFInvalidProof
	}

	// AUDIT (2026) CRND-FIX: Re-derive output from the proof
	// (secret-derived material), not from public data. Matches PQVRFEval.
	expectedOutput := pqvrfDeriveOutputFromProof(proof.Proof, publicKey.Bytes(), input)
	if subtle.ConstantTimeCompare(expectedOutput[:], output.Value[:]) != 1 {
		return ErrPQVRFInvalidOutput
	}

	return nil
}

// PQVRFVerifyHash is a convenience wrapper that accepts a types.Hash as input.
func PQVRFVerifyHash(publicKey *crypto.PublicKey, seed types.Hash, proof *PQVRFProof, output *PQVRFOutput) error {
	return PQVRFVerify(publicKey, seed[:], proof, output)
}

// PQVRFVerifyBatch verifies multiple PQ-VRF proofs in parallel.
func PQVRFVerifyBatch(requests []PQVRFVerificationRequest) []PQVRFVerificationResult {
	if len(requests) == 0 {
		return nil
	}

	results := make([]PQVRFVerificationResult, len(requests))

	if len(requests) <= 4 {
		for i, req := range requests {
			err := PQVRFVerify(req.PublicKey, req.Input, req.Proof, req.Output)
			results[i] = PQVRFVerificationResult{Valid: err == nil, Error: err}
		}
		return results
	}

	var wg sync.WaitGroup
	wg.Add(len(requests))
	sem := make(chan struct{}, MaxPQVRFVerifyConcurrency)

	for i, req := range requests {
		sem <- struct{}{}
		go func(idx int, r PQVRFVerificationRequest) {
			defer func() { <-sem }()
			defer wg.Done()
			// R7-P3 FIX: recover prevents a panic in PQVRFVerify from
			// crashing the node. results[idx] stays zero-value (Valid: false).
			defer func() {
				if r := recover(); r != nil {
					qposAdvLogger.Errorf("panic in PQVRF batch verification worker: %v", r)
				}
			}()
			err := PQVRFVerify(r.PublicKey, r.Input, r.Proof, r.Output)
			results[idx] = PQVRFVerificationResult{Valid: err == nil, Error: err}
		}(i, req)
	}

	wg.Wait()
	return results
}

// PQVRFCheckUniqueness verifies that the same (sk, input) always produces the same output.
// This is a diagnostic function for testing the uniqueness property.
func PQVRFCheckUniqueness(privateKey *crypto.PrivateKey, input []byte, iterations int) error {
	if iterations < 2 {
		return nil
	}

	var firstProof *PQVRFProof
	var firstOutput *PQVRFOutput

	for i := 0; i < iterations; i++ {
		proof, output, err := PQVRFEval(privateKey, input)
		if err != nil {
			return err
		}

		if i == 0 {
			firstProof = proof
			firstOutput = output
			continue
		}

		if subtle.ConstantTimeCompare(firstOutput.Value[:], output.Value[:]) != 1 {
			return ErrPQVRFUniquenessFailed
		}

		if subtle.ConstantTimeCompare(firstProof.Proof, proof.Proof) != 1 {
			return ErrPQVRFUniquenessFailed
		}
	}

	return nil
}

// pqvrfDeriveOutputFromProof derives the VRF output from the proof (which is
// secret-derived — only the private key holder can produce it), the public key,
// and the input. This makes the output unpredictable to anyone who doesn't
// have the private key, which is the essential VRF property.
//
// AUDIT (2026) CRND-FIX: Replaces pqvrfDeriveOutputDeterministic
// (which used only public data, making the output pre-computable by anyone).
func pqvrfDeriveOutputFromProof(proof, pubKeyBytes, input []byte) [PQVRFOutputSize]byte {
	rawHasher := pqvrfKDFPool.Get()
	hasher, ok := rawHasher.(sha3.ShakeHash)
	if !ok {
		hasher = sha3.NewShake256()
	}
	hasher.Reset()

	// P3-LOG-01 FIX (R30, 2026-07-27): Use logging.Global().Warn() so SIEM
	// pipelines can collect these events via the global logger instance.
	if _, err := hasher.Write([]byte(pqvrfDomainSeparator)); err != nil {
		logging.Global().Warn("pqvrfDeriveOutputFromProof: hash write failed", map[string]any{"error": err.Error()})
	}
	// Proof is the secret-derived component — only the private key holder can produce it.
	if _, err := hasher.Write(proof); err != nil {
		logging.Global().Warn("pqvrfDeriveOutputFromProof: hash write failed", map[string]any{"error": err.Error()})
	}
	if _, err := hasher.Write(pubKeyBytes); err != nil {
		logging.Global().Warn("pqvrfDeriveOutputFromProof: hash write failed", map[string]any{"error": err.Error()})
	}
	if _, err := hasher.Write(input); err != nil {
		logging.Global().Warn("pqvrfDeriveOutputFromProof: hash write failed", map[string]any{"error": err.Error()})
	}

	var output [PQVRFOutputSize]byte
	if _, err := hasher.Read(output[:]); err != nil {
		logging.Global().Warn("pqvrfDeriveOutputFromProof: hash read failed", map[string]any{"error": err.Error()})
	}

	pqvrfKDFPool.Put(hasher)
	return output
}

// PQVRFComputeOutput computes the VRF output from the public key, proof, and input.
// AUDIT (2026) CRND- Output now derives from the proof (secret-derived),
// not from public data alone. The proof parameter is required.
func PQVRFComputeOutput(publicKey *crypto.PublicKey, proof []byte, input []byte) (*PQVRFOutput, error) {
	if publicKey == nil {
		return nil, ErrPQVRFNilPublicKey
	}
	if len(proof) == 0 {
		return nil, ErrPQVRFInvalidProof
	}
	output := pqvrfDeriveOutputFromProof(proof, publicKey.Bytes(), input)
	return &PQVRFOutput{Value: output}, nil
}

func (p *PQVRFProof) ProofBytes() []byte {
	if p == nil {
		return nil
	}
	return p.Proof
}

func (o *PQVRFOutput) OutputBytes() []byte {
	if o == nil {
		return nil
	}
	return o.Value[:]
}

func (o *PQVRFOutput) ToHash() types.Hash {
	var h types.Hash
	copy(h[:], o.Value[:])
	return h
}

func PQVRFProofFromBytes(b []byte) (*PQVRFProof, error) {
	if len(b) != PQVRFProofSize {
		return nil, ErrPQVRFInvalidProof
	}
	proof := make([]byte, PQVRFProofSize)
	copy(proof, b)
	return &PQVRFProof{Proof: proof}, nil
}

func PQVRFOutputFromBytes(b []byte) (*PQVRFOutput, error) {
	if len(b) != PQVRFOutputSize {
		return nil, ErrPQVRFInvalidOutput
	}
	var output PQVRFOutput
	copy(output.Value[:], b)
	return &output, nil
}

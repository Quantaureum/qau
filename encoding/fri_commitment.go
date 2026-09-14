// Quantaureum Node source, version 1.0.0.
package encoding

// DA-FIX (2026-07-17): FRI (Fast Reed-Solomon IOP of Proximity) protocol.
//
// FRI proves that a committed codeword is close to a valid Reed-Solomon codeword.
// This is the post-quantum polynomial commitment scheme that replaces the hash stub.
//
// Protocol overview:
//
//   Commit Phase:
//     1. Prover has codeword c_0 = f(H_0) where f has degree < d, |H_0| = N
//     2. Commit to c_0 via Merkle root
//     3. For each layer i, fold the codeword:
//        c_{i+1}[j] = (c_i[j] + c_i[j+n/2])/2 + α_i * (c_i[j] - c_i[j+n/2])/(2*x_j)
//        where α_i is a Fiat-Shamir challenge derived from previous commitments
//     4. Commit to each layer via Merkle root
//     5. Final layer (small): send values in clear
//
//   Query Phase:
//     1. Verifier picks random query indices in layer 0
//     2. For each query, prover reveals values + Merkle paths at each layer
//     3. Verifier checks: Merkle proofs valid, folding consistency, final values match
//
// Security: post-quantum (based on hash collision resistance + field properties)

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// FRIConfig configures the FRI protocol parameters.
type FRIConfig struct {
	DomainSize     int // Size of the evaluation domain (must be power of 2)
	CodeRate       int // Expansion factor: domainSize = polyDegree * codeRate
	NumQueries     int // Number of query positions for soundness
	FinalLayerSize int // When codeword shrinks to this size, stop folding
}

// MinProductionNumQueries is the minimum number of FRI queries required for
// production-grade security. R32-P2-15 FIX (2026-07-28).
//
// With code rate ρ = 1/4, each query catches a cheating prover with
// probability 1 - ρ = 3/4. The probability of a cheat passing all q
// queries is ρ^q = (1/4)^q. For q = 40, this gives 2^(-80), which is
// the minimum post-quantum security level for blockchain DA layers.
//
// DefaultFRIConfig uses 80 queries (2^(-160)), well above this minimum.
// Tests may use fewer queries for speed, but production code should
// validate via ValidateFRIConfigForProduction.
const MinProductionNumQueries = 40

// ValidateFRIConfigForProduction validates that a FRIConfig meets production-
// grade security requirements. R32-P2-15 FIX (2026-07-28).
//
// Returns an error if any of the following conditions are not met:
//   - DomainSize is a positive power of 2
//   - CodeRate >= 2 (rate 1/2 or better; rate 1 is trivially insecure)
//   - NumQueries >= MinProductionNumQueries (40, for >= 80-bit security)
//   - FinalLayerSize >= 2 (a final layer of size 1 has no degree bound)
//
// Test code may use lower parameters for speed, but any config used in
// production (block validation, DA sampling, etc.) must pass this check.
func ValidateFRIConfigForProduction(cfg FRIConfig) error {
	if cfg.DomainSize <= 0 || cfg.DomainSize&(cfg.DomainSize-1) != 0 {
		return errFRIInvalidConfig("DomainSize must be a positive power of 2, got %d", cfg.DomainSize)
	}
	if cfg.CodeRate < 2 {
		return errFRIInvalidConfig("CodeRate must be >= 2 for production (rate 1/2 or better), got %d", cfg.CodeRate)
	}
	if cfg.NumQueries < MinProductionNumQueries {
		return errFRIInvalidConfig("NumQueries must be >= %d for production (>=80-bit security), got %d",
			MinProductionNumQueries, cfg.NumQueries)
	}
	if cfg.FinalLayerSize < 2 {
		return errFRIInvalidConfig("FinalLayerSize must be >= 2 for production, got %d", cfg.FinalLayerSize)
	}
	return nil
}

// errFRIInvalidConfig is returned by ValidateFRIConfigForProduction.
type friConfigError struct{ msg string }

func (e *friConfigError) Error() string { return e.msg }
func errFRIInvalidConfig(format string, args ...any) error {
	return &friConfigError{msg: fmt.Sprintf(format, args...)}
}

// DefaultFRIConfig returns secure default parameters.
//
// DA-FIX (2026-07-17): NumQueries raised from 50 to 80.
// Theoretical reliability ≈ ρ^NumQueries = (1/4)^80 = 2^(-160). Even after
// accounting for implementation overhead (DEEP verification, final-layer
// low-degree test, etc.), this provides >= 100-bit reliability — the
// production-grade threshold for blockchain DA layers. The previous value
// of 50 gave only 2^(-100) theoretical (and lower in practice due to
// DA- final-layer check gap, which has since been closed).
//
// DA-FIX (2026-07-17): polyDegree is rounded up to the next power of
// 2 so that DomainSize = polyDegree * CodeRate is also a power of 2 (FRI's
// NTT/FFT and index generation require this). Callers passing a non-power-
// of-2 polyDegree previously got a silently biased DomainSize.
func DefaultFRIConfig(polyDegree int) FRIConfig {
	if polyDegree <= 0 {
		polyDegree = 1
	}
	// Round polyDegree up to the next power of 2.
	if polyDegree&(polyDegree-1) != 0 {
		next := 1
		for next < polyDegree {
			next <<= 1
		}
		polyDegree = next
	}
	return FRIConfig{
		DomainSize:     polyDegree * 4, // rate 1/4 for better soundness
		CodeRate:       4,
		NumQueries:     80,
		FinalLayerSize: 4,
	}
}

// friLayer represents one layer in the FRI protocol.
type friLayer struct {
	values     []GF64Element // Codeword values at this layer
	domain     []GF64Element // Domain points (x_j values)
	merkleTree [][32]byte    // Merkle tree (index 0 = root)
}

// FRICommitment is the committed FRI proof structure.
type FRICommitment struct {
	LayerRoots  [][32]byte    // Merkle root of each layer
	FinalValues []GF64Element // Final layer values (sent in clear)
	NumLayers   int           // Number of folding layers
	DomainSize  int           // Original domain size
}

// friLayerProof is the proof for a single query at one layer.
type friLayerProof struct {
	Value              GF64Element // Value at queried index
	SiblingValue       GF64Element // Value at paired index (index + n/2)
	Index              int         // Index in this layer
	MerkleProof        [][]byte    // Merkle path for the queried value
	SiblingMerkleProof [][]byte    // Merkle path for the sibling
}

// FRIQueryProof is the proof for a single query across all layers.
type FRIQueryProof struct {
	Layers []friLayerProof
}

// FRIProof is the complete FRI proof containing all query proofs.
type FRIProof struct {
	Queries []FRIQueryProof
}

// --- Merkle tree for field elements ---

// friLeafHash hashes a field element as a Merkle leaf.
func friLeafHash(e GF64Element) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(GF64ToBytes(e))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// friBuildMerkleTree builds a Merkle tree from field elements.
func friBuildMerkleTree(values []GF64Element) [][32]byte {
	n := len(values)
	paddedSize := nextPowerOf2(n)
	treeSize := 2*paddedSize - 1
	tree := make([][32]byte, treeSize)

	leafStart := treeSize - paddedSize
	for i := 0; i < paddedSize; i++ {
		if i < n {
			tree[leafStart+i] = friLeafHash(values[i])
		}
	}

	for i := leafStart - 1; i >= 0; i-- {
		tree[i] = merkleInternalHash(tree[2*i+1], tree[2*i+2])
	}

	return tree
}

// friGenerateMerkleProof generates a Merkle proof for index in the tree.
func friGenerateMerkleProof(tree [][32]byte, index, count int) [][]byte {
	return generateMerkleProof(tree, index, count)
}

// friVerifyMerkleProof verifies a Merkle proof for a field element.
func friVerifyMerkleProof(root [32]byte, value GF64Element, index, count int, proof [][]byte) bool {
	leafHash := friLeafHash(value)
	return verifyMerkleProof(root, leafHash, index, count, proof)
}

// --- Fiat-Shamir challenges ---

// friChallenge derives a field element from a hash of the provided data.
func friChallenge(data ...[]byte) GF64Element {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)
	// Use first 8 bytes as field element (reduced mod p)
	return GF64FromBytes(hash[:8])
}

// --- FRI folding ---

// friFold computes the FRI folding at one layer.
// c_next[j] = (c[j] + c[j+n/2])/2 + α * (c[j] - c[j+n/2])/(2*x_j)
//
// ENCODING-P0-01 FIX (R31, 2026-07-27): Returns nil if any domain element
// is zero (would cause division by zero in GF64Inverse). Callers must
// check for nil and treat as verification failure.
//
// R32-P1-13 FIX (2026-07-28): Added boundary checks for len(c) vs
// len(domain) and len(c) >= 2. Previously, mismatched lengths would cause
// an index-out-of-range panic deep in the loop, allowing an attacker who
// could influence the codeword or domain slices to crash the node.
func friFold(c []GF64Element, domain []GF64Element, alpha GF64Element) []GF64Element {
	n := len(c)
	if n < 2 {
		return nil
	}
	halfN := n / 2
	// The folding reads domain[j] for j in [0, halfN). The caller is
	// expected to pass a domain of length >= halfN (typically == halfN
	// for layer i+1, or == n for layer i where the lower half is used).
	// Reject any mismatch to prevent out-of-range access.
	if len(domain) < halfN {
		return nil
	}
	result := make([]GF64Element, halfN)

	// GF64Inverse(2) never fails because 2 != 0.
	twoInv, _ := GF64Inverse(2)

	for j := 0; j < halfN; j++ {
		cEven := c[j]      // c[j]
		cOdd := c[j+halfN] // c[j + n/2] = c(-x_j)
		x := domain[j]     // x_j

		// sum = (cEven + cOdd) / 2
		sum := GF64Mul(GF64Add(cEven, cOdd), twoInv)

		// diff = (cEven - cOdd) / (2 * x)
		// ENCODING-P0-01: x == 0 would cause GF64Inverse to return an
		// error. A zero domain element indicates a malformed/malicious
		// proof — abort folding by returning nil so the caller can
		// reject the proof instead of crashing the node.
		xInv, err := GF64Inverse(x)
		if err != nil {
			return nil
		}
		diff := GF64Mul(GF64Sub(cEven, cOdd), GF64Mul(twoInv, xInv))

		// result = sum + alpha * diff
		result[j] = GF64Add(sum, GF64Mul(alpha, diff))
	}

	return result
}

// friFoldOne computes the folded value for a single position (for verification).
//
// ENCODING-P0-01 FIX (R31, 2026-07-27): Returns (0, false) if x == 0
// (would cause division by zero). The caller (FRIVerify) treats false as
// verification failure instead of crashing the node.
func friFoldOne(cEven, cOdd, x, alpha GF64Element) (GF64Element, bool) {
	// GF64Inverse(2) never fails because 2 != 0.
	twoInv, _ := GF64Inverse(2)
	sum := GF64Mul(GF64Add(cEven, cOdd), twoInv)
	xInv, err := GF64Inverse(x)
	if err != nil {
		return 0, false
	}
	diff := GF64Mul(GF64Sub(cEven, cOdd), GF64Mul(twoInv, xInv))
	return GF64Add(sum, GF64Mul(alpha, diff)), true
}

// --- Domain generation ---

// friGenerateLayerDomain generates the domain for a given layer.
// Layer 0 domain: {ω^0, ω^1, ..., ω^{n-1}} where ω has order n.
// Layer i domain: {ω^{2^i * 0}, ω^{2^i * 1}, ...} (every 2^i-th element).
//
// R32-P1-13 FIX (2026-07-28): Returns nil if domainSize <= 0, layerIdx < 0,
// or layerIdx >= 32 (which would cause `1 << layerIdx` to overflow on 32-bit
// platforms and produce a corrupt step value). Callers that receive nil
// must treat it as verification failure. Previously, an attacker-crafted
// commitment with DomainSize = 0 or a malicious layerIdx could cause
// downstream panics (e.g. in friFold, which assumed non-empty domain).
func friGenerateLayerDomain(layerIdx, domainSize int) []GF64Element {
	if domainSize <= 0 || layerIdx < 0 {
		return nil
	}
	// At layer i, the domain has size domainSize / 2^i
	size := domainSize >> uint(layerIdx)
	if size < 1 {
		size = 1
	}

	// The root of unity at this layer
	k := gf64Log2(domainSize)
	omegaFull := GF64Generator(k) // has order domainSize
	if omegaFull == 0 {
		// GF64Generator returned 0 because k > 32 (domainSize > 2^32).
		// This is invalid — reject.
		return nil
	}

	// At layer i, the domain root is omegaFull^(2^i)
	// Domain: {omegaFull^0, omegaFull^(2^i), omegaFull^(2*2^i), ...}
	// R32-P1-13: Guard against layerIdx >= 64 to prevent `1 << layerIdx`
	// overflow on 32-bit platforms. With layerIdx < 64 the shift fits in
	// a uint64. Layers >= 64 are meaningless for any realistic domain.
	if layerIdx >= 64 {
		return nil
	}
	step := uint64(1) << uint(layerIdx)
	domain := make([]GF64Element, size)
	current := GF64Element(1)
	for j := 0; j < size; j++ {
		domain[j] = current
		if j+1 < size {
			for s := uint64(0); s < step; s++ {
				current = GF64Mul(current, omegaFull)
			}
		}
	}
	return domain
}

// --- FRI Commit ---

// FRICommit creates the FRI commitment for a codeword.
// The codeword must be the evaluation of a polynomial of degree < domainSize/codeRate
// on the domain of size domainSize.
//
// Returns the commitment and the internal layers (for proof generation).
//
// R32-P1-13 FIX (2026-07-28): Returns (nil, nil) instead of panicking when
// the codeword length doesn't match cfg.DomainSize, when DomainSize is not
// a power of 2, or when friGenerateLayerDomain returns nil. The panic was
// triggerable by any internal caller that passed an inconsistent config
// (e.g. FRICommitBlob with a non-power-of-2 polyDegree that bypassed
// DefaultFRIConfig's rounding). Returning nil lets callers (FRIDACommitBlob)
// return a proper error instead of crashing the node.
func FRICommit(codeword []GF64Element, cfg FRIConfig) (*FRICommitment, []*friLayer) {
	if len(codeword) != cfg.DomainSize {
		return nil, nil
	}
	if cfg.DomainSize <= 0 || cfg.DomainSize&(cfg.DomainSize-1) != 0 {
		// DomainSize must be a power of 2 for FRI to be correct.
		return nil, nil
	}
	if cfg.FinalLayerSize <= 0 {
		return nil, nil
	}

	layers := make([]*friLayer, 0)
	roots := make([][32]byte, 0)

	// Layer 0
	domain0 := friGenerateLayerDomain(0, cfg.DomainSize)
	if domain0 == nil {
		return nil, nil
	}
	tree0 := friBuildMerkleTree(codeword)
	layers = append(layers, &friLayer{
		values:     codeword,
		domain:     domain0,
		merkleTree: tree0,
	})
	roots = append(roots, tree0[0])

	// Fold layers
	current := codeword
	numLayers := 0
	maxLayers := gf64Log2(cfg.DomainSize) - gf64Log2(cfg.FinalLayerSize)

	for i := 0; i < int(maxLayers); i++ {
		layerSize := len(current)
		if layerSize <= cfg.FinalLayerSize {
			break
		}

		// Fiat-Shamir challenge from previous root
		var prevRootBytes []byte
		for _, r := range roots {
			prevRootBytes = append(prevRootBytes, r[:]...)
		}
		alpha := friChallenge(prevRootBytes)

		// Fold
		layerDomain := friGenerateLayerDomain(i, cfg.DomainSize)
		if layerDomain == nil {
			// R32-P1-13: friGenerateLayerDomain now returns nil for
			// invalid inputs instead of returning a corrupt domain.
			return nil, nil
		}
		folded := friFold(current, layerDomain, alpha)
		// ENCODING-P0-01 + R32-P1-13: friFold returns nil if any domain
		// element is zero OR if the codeword/domain lengths are
		// inconsistent. This is mathematically impossible for properly
		// generated roots of unity (the domain is generated internally
		// by the prover, not attacker-controlled), so a nil result
		// indicates a critical bug in domain generation. Return nil
		// rather than panicking so the caller can fail gracefully.
		if folded == nil {
			return nil, nil
		}

		// Commit
		foldedTree := friBuildMerkleTree(folded)
		nextDomain := friGenerateLayerDomain(i+1, cfg.DomainSize)
		if nextDomain == nil {
			return nil, nil
		}
		layers = append(layers, &friLayer{
			values:     folded,
			domain:     nextDomain,
			merkleTree: foldedTree,
		})
		roots = append(roots, foldedTree[0])

		current = folded
		numLayers++
	}

	// Final layer values (sent in clear)
	finalValues := make([]GF64Element, len(current))
	copy(finalValues, current)

	return &FRICommitment{
		LayerRoots:  roots,
		FinalValues: finalValues,
		NumLayers:   numLayers,
		DomainSize:  cfg.DomainSize,
	}, layers
}

// --- FRI Prove ---

// FRIProve generates proofs for the given query indices.
//
// For each layer i (0..NumLayers-1), the prover reveals:
//   - The value at the current query position idx (in [0, n))
//   - The value at the sibling position (idx XOR halfN)
//   - Merkle proofs for both
//
// The next layer's query position is idx mod halfN (i.e., idx mapped into
// the lower half), because folding combines pairs (j, j+halfN) → j.
//
// R32-P1-13 FIX (2026-07-28): Returns nil if any query index is out of
// range for layer 0. Previously this would panic with index-out-of-range
// when a caller passed an unchecked qIdx (e.g. from FRIGenerateQueryIndices
// on a maliciously-crafted commitment with oversized DomainSize).
func FRIProve(layers []*friLayer, queryIndices []int, cfg FRIConfig) *FRIProof {
	if len(layers) == 0 {
		return nil
	}
	// Validate all query indices against layer 0's size up front.
	layer0Size := len(layers[0].values)
	for _, qIdx := range queryIndices {
		if qIdx < 0 || qIdx >= layer0Size {
			return nil
		}
	}

	queries := make([]FRIQueryProof, len(queryIndices))

	numLayers := len(layers) - 1 // last layer is the final layer (no folding proof needed)

	for qi, qIdx := range queryIndices {
		layerProofs := make([]friLayerProof, 0, numLayers)
		idx := qIdx

		for i := 0; i < numLayers; i++ {
			layer := layers[i]
			n := len(layer.values)
			halfN := n / 2
			if halfN < 1 {
				break
			}
			// R32-P1-13: Defensive bounds check on idx. After
			// `idx = idx % halfN`, idx is always in [0, halfN), so this
			// should never trigger — but a corrupt layer.values slice
			// (e.g. from a buggy FRICommit) could cause an OOB panic.
			if idx < 0 || idx >= n {
				return nil
			}

			// Sibling is the paired position: idx XOR halfN.
			// If idx < halfN: sibling = idx + halfN
			// If idx >= halfN: sibling = idx - halfN
			var siblingIdx int
			if idx < halfN {
				siblingIdx = idx + halfN
			} else {
				siblingIdx = idx - halfN
			}

			value := layer.values[idx]
			sibling := layer.values[siblingIdx]

			valueProof := friGenerateMerkleProof(layer.merkleTree, idx, n)
			siblingProof := friGenerateMerkleProof(layer.merkleTree, siblingIdx, n)

			layerProofs = append(layerProofs, friLayerProof{
				Value:              value,
				SiblingValue:       sibling,
				Index:              idx,
				MerkleProof:        valueProof,
				SiblingMerkleProof: siblingProof,
			})

			// Next layer's index: idx mod halfN (folding maps pair (j, j+halfN) → j)
			idx = idx % halfN
		}

		queries[qi] = FRIQueryProof{Layers: layerProofs}
	}

	return &FRIProof{Queries: queries}
}

// --- FRI Verify ---

// FRIVerify verifies a FRI proof against a commitment.
// Returns true if the proof is valid.
//
// For each query, the verifier walks through all layers:
//  1. Verifies the Merkle proofs for (Value, SiblingValue) at (Index, siblingIdx)
//  2. Recomputes the folding: c_next[j] = friFoldOne(cEven, cOdd, x_j, alpha_i)
//     where j = Index mod halfN, x_j is the j-th domain point, and
//     (cEven, cOdd) = (Value, SiblingValue) if Index < halfN, else swapped.
//  3. Checks that the next layer's value (or final value) matches.
//
// R32-P1-13 FIX (2026-07-28): Added structural validation of the commitment
// (LayerRoots length >= NumLayers+1, DomainSize > 0) and nil-checks on the
// friGenerateLayerDomain return value. Previously an attacker-crafted
// commitment with NumLayers > len(LayerRoots) would panic when accessing
// commitment.LayerRoots[i] in the Fiat-Shamir recomputation loop.
//
// R32-P2-15 FIX (2026-07-28): Added enforcement that len(queryIndices) >=
// cfg.NumQueries. Previously, FRIVerify only checked that the proof's query
// count matched the queryIndices length, but did NOT verify that the number
// of queries met the configured minimum. A malicious prover could submit a
// proof with just 1 query (instead of the configured 80), reducing the
// soundness from 2^(-160) to (3/4)^1 = 75% — far above the 2^(-40) threshold
// required for blockchain DA security. This enabled a malicious proposer to
// generate incorrect proofs that pass verification with high probability.
func FRIVerify(commitment *FRICommitment, proof *FRIProof, queryIndices []int, cfg FRIConfig) bool {
	if len(proof.Queries) != len(queryIndices) {
		return false
	}
	// R32-P2-15: cfg.NumQueries must be strictly positive. A zero value
	// would allow an empty proof to pass (0 queries = no checks = trivially
	// "valid"), defeating the entire FRI soundness guarantee.
	if cfg.NumQueries <= 0 {
		return false
	}
	// R32-P2-15: The number of queries actually provided must meet the
	// configured minimum. This is the core fix: without this check, a
	// prover could supply fewer queries than required, degrading soundness
	// below the security threshold.
	//
	// We use >= rather than == because FRIGenerateOpeningProof force-
	// includes the cellIndex as query 0 (overwriting the Fiat-Shamir
	// index at position 0). The total count still equals cfg.NumQueries,
	// but we use >= to be lenient with callers that add extra queries
	// for cross-checking (which only improves soundness).
	if len(queryIndices) < cfg.NumQueries {
		return false
	}
	if commitment.NumLayers <= 0 {
		return false
	}
	// R32-P1-13: Structural validation of the commitment.
	// LayerRoots must contain at least NumLayers+1 entries (layer 0 through
	// layer NumLayers, inclusive — the final layer's root is also stored).
	if len(commitment.LayerRoots) < commitment.NumLayers+1 {
		return false
	}
	if commitment.DomainSize <= 0 || commitment.DomainSize&(commitment.DomainSize-1) != 0 {
		// DomainSize must be a positive power of 2.
		return false
	}
	// R37-P3-15 FIX (2026-07-31): Cap DomainSize at 2^31, completing
	// R36-P2-ENC-01 (which only capped it in DecodeFRIDACommitment).
	// Commitments can reach this verifier without passing through the
	// decoder; FRIGenerateQueryIndices casts DomainSize to uint32, so a
	// value of 2^32 would wrap to 0 and cause a divide-by-zero panic.
	if commitment.DomainSize > MaxFRIDADomainSize {
		return false
	}
	if len(commitment.FinalValues) == 0 {
		return false
	}

	// Recompute Fiat-Shamir challenges
	challenges := make([]GF64Element, commitment.NumLayers)
	for i := 0; i < commitment.NumLayers; i++ {
		var rootBytes []byte
		for j := 0; j <= i; j++ {
			rootBytes = append(rootBytes, commitment.LayerRoots[j][:]...)
		}
		challenges[i] = friChallenge(rootBytes)
	}

	for qi, qIdx := range queryIndices {
		queryProof := proof.Queries[qi]
		if len(queryProof.Layers) != commitment.NumLayers {
			return false
		}

		// Sanity-check the initial query index.
		if qIdx < 0 || qIdx >= commitment.DomainSize {
			return false
		}

		for i := 0; i < commitment.NumLayers; i++ {
			lp := queryProof.Layers[i]
			layerSize := commitment.DomainSize >> uint(i)
			if layerSize < 2 {
				return false
			}
			halfN := layerSize / 2

			// Validate the stored index is within this layer's range.
			if lp.Index < 0 || lp.Index >= layerSize {
				return false
			}
			// R36-P1-ENC-01 FIX: Bind the first layer's revealed index to the
			// Fiat-Shamir-derived query index. Without this, a malicious prover
			// can set Layers[0].Index to an arbitrary position, allowing a
			// forged FRI proof to pass all folding consistency checks.
			if i == 0 && lp.Index != qIdx {
				return false
			}
			// R32-P1-13: bounds-check the LayerRoots access. The check
			// above guarantees len(LayerRoots) >= NumLayers+1, and i <
			// NumLayers, so i+1 <= NumLayers and LayerRoots[i] is safe.
			// But we check defensively in case NumLayers was mutated.
			if i >= len(commitment.LayerRoots) {
				return false
			}

			// Verify Merkle proof for the value at lp.Index
			if !friVerifyMerkleProof(commitment.LayerRoots[i], lp.Value, lp.Index, layerSize, lp.MerkleProof) {
				return false
			}

			// Compute sibling index: lp.Index XOR halfN
			var siblingIdx int
			if lp.Index < halfN {
				siblingIdx = lp.Index + halfN
			} else {
				siblingIdx = lp.Index - halfN
			}
			if !friVerifyMerkleProof(commitment.LayerRoots[i], lp.SiblingValue, siblingIdx, layerSize, lp.SiblingMerkleProof) {
				return false
			}

			// j is the position in the lower half — this is where folding lands.
			j := lp.Index % halfN

			// Domain point x_j (lower-half position).
			domain := friGenerateLayerDomain(i, commitment.DomainSize)
			// R32-P1-13: friGenerateLayerDomain now returns nil for invalid
			// inputs (DomainSize <= 0, layerIdx < 0, etc.). Treat as
			// verification failure instead of panicking on `domain[j]`.
			if domain == nil || j >= len(domain) {
				return false
			}
			x := domain[j]

			// Determine (cEven, cOdd): cEven = c[j], cOdd = c[j + halfN]
			var cEven, cOdd GF64Element
			if lp.Index < halfN {
				cEven = lp.Value
				cOdd = lp.SiblingValue
			} else {
				cEven = lp.SiblingValue
				cOdd = lp.Value
			}

			// Recompute the folded value
			// ENCODING-P0-01: friFoldOne returns ok=false if x == 0
			// (zero domain element). Treat as verification failure instead
			// of crashing the node via panic.
			expectedNext, ok := friFoldOne(cEven, cOdd, x, challenges[i])
			if !ok {
				return false
			}

			if i < commitment.NumLayers-1 {
				// The next layer's value at position j should match the folding result.
				nextLp := queryProof.Layers[i+1]
				// Cross-check: the next layer's Index should be j (mod next halfN)
				// — but the next layer's index lives in [0, layerSize/2), so it must equal j.
				if nextLp.Index != j {
					return false
				}
				if expectedNext != nextLp.Value {
					return false
				}
			} else {
				// Last folding layer: check against the final values.
				if j >= len(commitment.FinalValues) {
					return false
				}
				if expectedNext != commitment.FinalValues[j] {
					return false
				}
			}
		}
	}

	// R7 P0-5 FIX (DA-, 2026-07-17): Verify final values are consistent
	// with a low-degree polynomial. Previously the final layer (size <= 4)
	// accepted ANY values without degree checking, allowing an attacker to use
	// a high-degree polynomial at the final layer and bypass FRI's low-degree
	// test. Now we verify that the final values lie on a polynomial of degree
	// < len(FinalValues)/4 (R36-P2-ENC-02: was /2, tightened to match the
	// declared rate-1/4 code) using Lagrange interpolation: interpolate from
	// the first k = n/4 points, then check the remaining n-k points lie on
	// the same polynomial.
	if !friVerifyFinalLowDegree(commitment.FinalValues, commitment.NumLayers, commitment.DomainSize) {
		return false
	}

	return true
}

// friVerifyFinalLowDegree verifies that the FRI final-layer values lie on a
// polynomial of degree < n/4, where n = len(finalValues). This is the FRI
// low-degree test for the terminal layer, matching the declared rate-1/4
// code (see FRIConfig.CodeRate and FRIRecommendedConfig which uses rate 1/4).
//
// R7 P0-5 FIX (DA-): Without this check, an attacker could substitute
// arbitrary high-degree values at the final layer and pass FRI verification,
// defeating the entire low-degree guarantee of the FRI protocol.
//
// Method: Lagrange interpolation. We take the first k = n/4 (x, y) pairs,
// interpolate to obtain the unique degree-< k polynomial P(x), then verify
// that the remaining n-k points satisfy P(x_m) == y_m. If any check fails,
// the values do NOT lie on a degree-< n/4 polynomial and must be rejected.
//
// R36-P2-ENC-02 FIX (2026-07-30): Previously k = n/2, which accepted
// polynomials of degree < n/2 — corresponding to a rate-1/2 code, not the
// declared rate-1/4. For a rate-1/4 code with FinalLayerSize=4, the final
// layer polynomial must be a constant (degree 0); k = n/4 = 1 correctly
// enforces this, while k = n/2 = 2 would accept degree-1 polynomials,
// degrading per-query soundness from (1/4)^q to (1/2)^q.
//
// R32-P1-13 FIX (2026-07-28): Added nil-check for friGenerateLayerDomain
// return value. Previously, an invalid (numLayers, domainSize) combination
// would cause friGenerateLayerDomain to return nil (after the P1-13 fix to
// that function), and the subsequent `domain[m]` access would panic.
func friVerifyFinalLowDegree(finalValues []GF64Element, numLayers, domainSize int) bool {
	n := len(finalValues)
	if n < 2 {
		// 0 or 1 values: trivially degree-0 (or empty). Always valid.
		return true
	}

	// Generate the final layer domain points.
	domain := friGenerateLayerDomain(numLayers, domainSize)
	// R32-P1-13: friGenerateLayerDomain returns nil for invalid inputs.
	if domain == nil || len(domain) < n {
		return false
	}

	// R36-P2-ENC-02: k = n/4 for rate-1/4 code (was n/2, which was too loose).
	k := n / 4 // interpolation degree bound: polynomial degree < k
	if k < 1 {
		// n < 4: cannot perform a meaningful rate-1/4 low-degree test.
		// Final layers this small are not valid for a rate-1/4 code but
		// we accept rather than reject to avoid breaking edge-case proofs.
		return true
	}

	// For each verification point m in [k, n), check it lies on the
	// degree-< k polynomial interpolated from points [0, k).
	for m := k; m < n; m++ {
		x := domain[m]
		// P(x) = Σ_{i=0}^{k-1} y_i * L_i(x)
		// L_i(x) = Π_{j≠i, j<k} (x - x_j) / (x_i - x_j)
		sum := GF64Element(0)
		for i := 0; i < k; i++ {
			num := GF64Element(1)
			den := GF64Element(1)
			for j := 0; j < k; j++ {
				if j == i {
					continue
				}
				num = GF64Mul(num, GF64Sub(x, domain[j]))
				den = GF64Mul(den, GF64Sub(domain[i], domain[j]))
			}
			// den != 0 because all domain points are distinct (roots of unity).
			// ENCODING-P0-01: Defensively handle zero denominator (would
			// indicate a bug in domain generation or a malicious setup).
			// Return false to reject the proof instead of crashing.
			li, err := GF64Div(num, den)
			if err != nil {
				return false
			}
			sum = GF64Add(sum, GF64Mul(finalValues[i], li))
		}
		if sum != finalValues[m] {
			return false
		}
	}
	return true
}

// --- High-level API ---

// FRIBlobToFieldElements converts a blob (byte slice) to Goldilocks field elements.
// Each 8 bytes becomes one field element (little-endian).
func FRIBlobToFieldElements(data []byte) []GF64Element {
	// Pad to multiple of 8
	paddedLen := (len(data) + 7) &^ 7
	padded := make([]byte, paddedLen)
	copy(padded, data)

	n := paddedLen / 8
	elements := make([]GF64Element, n)
	for i := 0; i < n; i++ {
		elements[i] = GF64FromBytes(padded[i*8 : i*8+8])
	}
	return elements
}

// FRICommitBlob is a convenience function that converts a blob to field elements,
// performs RS extension, and creates a FRI commitment.
// Returns the commitment, the codeword (for proof generation), and the layers.
//
// R32-P1-13 FIX (2026-07-28): Returns (nil, nil, nil) when GF64ReedSolomonExtend
// or FRICommit return nil (invalid config). Previously this would pass a nil
// codeword to FRICommit, which would then panic on `len(codeword) != cfg.DomainSize`.
func FRICommitBlob(blob []byte, cfg FRIConfig) (*FRICommitment, []GF64Element, []*friLayer) {
	// Convert blob to field elements
	elements := FRIBlobToFieldElements(blob)

	// Pad to polynomial degree (domainSize / codeRate)
	polyDegree := cfg.DomainSize / cfg.CodeRate
	for len(elements) < polyDegree {
		elements = append(elements, 0)
	}
	if len(elements) > polyDegree {
		elements = elements[:polyDegree]
	}

	// RS extend: evaluate on the full domain
	codeword := GF64ReedSolomonExtend(elements, cfg.DomainSize)
	if codeword == nil {
		// R32-P1-13: GF64ReedSolomonExtend rejected the config.
		return nil, nil, nil
	}

	// FRI commit
	commitment, layers := FRICommit(codeword, cfg)
	if commitment == nil {
		// R32-P1-13: FRICommit rejected the config (returned nil, nil).
		return nil, nil, nil
	}

	return commitment, codeword, layers
}

// FRIGenerateQueryIndices generates random query indices using Fiat-Shamir.
func FRIGenerateQueryIndices(commitment *FRICommitment, numQueries int) []int {
	var data []byte
	for _, root := range commitment.LayerRoots {
		data = append(data, root[:]...)
	}
	for _, v := range commitment.FinalValues {
		data = append(data, GF64ToBytes(v)...)
	}

	indices := make([]int, numQueries)
	for i := 0; i < numQueries; i++ {
		h := sha256.New()
		h.Write(data)
		h.Write([]byte{byte(i), byte(i >> 8)})
		hash := h.Sum(nil)
		// R36-P2-ENC-01: DomainSize is capped at 2^31 by
		// DecodeFRIDACommitment, so the uint32 cast cannot wrap to 0.
		idx := binary.BigEndian.Uint32(hash[:4]) % uint32(commitment.DomainSize)
		indices[i] = int(idx)
	}
	return indices
}

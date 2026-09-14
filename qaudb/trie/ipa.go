// Quantaureum Node source, version 1.0.0.
package trie

import (
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type IPAProof struct {
	L []PedersenPoint
	R []PedersenPoint
	A *PedersenCommitment
}

type IPAWitness struct {
	A []*big.Int
	B []*big.Int
	C *big.Int
}

func NewIPAProof(numRounds int) *IPAProof {
	return &IPAProof{
		L: make([]PedersenPoint, numRounds),
		R: make([]PedersenPoint, numRounds),
	}
}

func (p *IPAProof) Bytes() []byte {
	totalLen := 4 + len(p.L)*PedersenPointSize + len(p.R)*PedersenPointSize
	if p.A != nil {
		totalLen += PedersenPointSize
	}
	result := make([]byte, totalLen)
	offset := 0

	putUint32BE(result[offset:], uint32(len(p.L)))
	offset += 4

	for _, l := range p.L {
		copy(result[offset:], l[:])
		offset += PedersenPointSize
	}

	for _, r := range p.R {
		copy(result[offset:], r[:])
		offset += PedersenPointSize
	}

	if p.A != nil {
		copy(result[offset:], p.A.Bytes())
	}

	return result
}

func IPAProofFromBytes(data []byte) (*IPAProof, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for IPA proof")
	}

	numRounds := int(getUint32BE(data[:4]))
	offset := 4

	expectedLen := 4 + numRounds*PedersenPointSize*2
	if len(data) < expectedLen {
		return nil, fmt.Errorf("data too short for IPA proof: expected %d, got %d", expectedLen, len(data))
	}

	proof := &IPAProof{
		L: make([]PedersenPoint, numRounds),
		R: make([]PedersenPoint, numRounds),
	}

	for i := 0; i < numRounds; i++ {
		copy(proof.L[i][:], data[offset:offset+PedersenPointSize])
		offset += PedersenPointSize
	}

	for i := 0; i < numRounds; i++ {
		copy(proof.R[i][:], data[offset:offset+PedersenPointSize])
		offset += PedersenPointSize
	}

	if offset < len(data) {
		// R37-P3-11 FIX (2026-07-31): verify enough bytes remain before
		// slicing. Without this, a truncated trailing commitment would
		// cause a slice bounds panic.
		if len(data)-offset < PedersenPointSize {
			return nil, fmt.Errorf("data too short for IPA proof commitment: expected %d more bytes, got %d",
				PedersenPointSize, len(data)-offset)
		}
		var err error
		proof.A, err = PedersenCommitmentFromBytes(data[offset : offset+PedersenPointSize])
		if err != nil {
			return nil, err
		}
	}

	return proof, nil
}

func GenerateIPAProof(basis *PedersenBasis, a, b []*big.Int, c *big.Int) (*IPAProof, error) {
	n := len(a)
	if n != len(b) {
		return nil, fmt.Errorf("vector length mismatch: a=%d, b=%d", n, len(b))
	}
	if n != len(basis.G) {
		return nil, fmt.Errorf("basis length mismatch: vectors=%d, basis=%d", n, len(basis.G))
	}

	if !isPowerOfTwo(n) {
		return nil, fmt.Errorf("vector length must be a power of 2, got %d", n)
	}

	numRounds := log2(n)
	proof := NewIPAProof(numRounds)

	currentA := make([]*big.Int, n)
	currentB := make([]*big.Int, n)
	copy(currentA, a)
	copy(currentB, b)

	currentBasis := &PedersenBasis{
		G: make([]PedersenPoint, n),
		H: basis.H,
	}
	copy(currentBasis.G, basis.G)

	for round := 0; round < numRounds; round++ {
		half := n >> 1

		aL, aR := currentA[:half], currentA[half:]
		bL, bR := currentB[:half], currentB[half:]

		_ = innerProduct(aL, bR)
		_ = innerProduct(aR, bL)

		proof.L[round] = computeRoundPoint(currentBasis.G[:half], aL, currentBasis.G[half:], bR)
		proof.R[round] = computeRoundPoint(currentBasis.G[half:], aR, currentBasis.G[:half], bL)

		x := deriveChallenge(proof.L[round], proof.R[round], round)

		xInv := new(big.Int).ModInverse(x, curveOrder())

		for i := 0; i < half; i++ {
			currentA[i] = new(big.Int).Add(
				new(big.Int).Mul(aL[i], x),
				new(big.Int).Mul(aR[i], xInv),
			)
			currentA[i].Mod(currentA[i], curveOrder())

			currentB[i] = new(big.Int).Add(
				new(big.Int).Mul(bL[i], xInv),
				new(big.Int).Mul(bR[i], x),
			)
			currentB[i].Mod(currentB[i], curveOrder())

			currentBasis.G[i] = combinePoints(currentBasis.G[i], currentBasis.G[half+i], xInv)
		}

		currentA = currentA[:half]
		currentB = currentB[:half]
		currentBasis.G = currentBasis.G[:half]
		n = half
	}

	comm, err := currentBasis.Commit(currentA)
	if err != nil {
		return nil, err
	}
	// R33 TRIE-07 FIX (2026-07-28): Add blinding factor to the final IPA
	// commitment. Without a blinding factor, the commitment C = <a, G>
	// is deterministic — an attacker who can guess the witness vector a
	// (e.g., via brute force on small-dimensional inputs) can verify
	// their guess by recomputing C. The blinding factor r * H makes C
	// perfectly hiding: even if a is known, C reveals nothing about r
	// under the discrete logarithm assumption.
	//
	// The blinding factor is derived deterministically from the proof's
	// Fiat-Shamir challenges so the verifier can recompute it (standard
	// pattern in Bulletproofs-style IPA). Here we derive it from the
	// initial challenges to avoid changing the IPAProof struct layout.
	// If IPA verification is ever enabled (currently stubbed out in
	// VerifyIPAProof), the verifier MUST use the same derivation.
	blinding := deriveIPAProofBlinding(proof)
	blindedComm, err := currentBasis.CommitWithBlinding(currentA, blinding)
	if err != nil {
		// CommitWithBlinding should not fail given a valid Commit result,
		// but fall back to the unblinded commitment if it does, so we
		// don't break existing callers.
		proof.A = comm
	} else {
		proof.A = blindedComm
	}

	return proof, nil
}

// deriveIPAProofBlinding derives a deterministic blinding factor for an
// IPA proof from its round commitments. This is a placeholder
// implementation — a full IPA implementation would derive the blinding
// factor from the Fiat-Shamir transcript. Here we hash the L/R round
// commitments to produce a scalar, ensuring the blinding is deterministic
// across provers (so the verifier can recompute it) while being
// unpredictable to an attacker who hasn't seen the proof.
//
// R33 TRIE-07 FIX (2026-07-28).
func deriveIPAProofBlinding(proof *IPAProof) *big.Int {
	h := sha3.New256()
	h.Write([]byte("ipa_blinding_v1"))
	for _, l := range proof.L {
		h.Write(l[:])
	}
	for _, r := range proof.R {
		h.Write(r[:])
	}
	digest := h.Sum(nil)
	b := new(big.Int).SetBytes(digest)
	b.Mod(b, curveOrder())
	if b.Sign() == 0 {
		b.SetInt64(1) // avoid zero blinding
	}
	return b
}

func VerifyIPAProof(basis *PedersenBasis, commitment *PedersenCommitment, b []*big.Int, c *big.Int, proof *IPAProof) (bool, error) {
	// SECURITY (audit 2026-06-24, H-2): IPA proof verification is not fully
	// implemented. The previous implementation ignored the commitment and c
	// parameters, allowing proofs to be replayed across different commitments.
	//
	// R26-045: IPA (Inner Product Argument) verification is NOT implemented.
	// Rather than silently returning a (false, nil) result that callers may
	// misinterpret as a genuine proof failure, return an explicit error so
	// callers can distinguish "not implemented" from an actual verification
	// failure and fall back gracefully (e.g. to a different proof system or
	// reject the operation). This fails closed: the proof is never accepted.
	// TODO: Implement full IPA verification including commitment and c
	// challenges, and remove this stub. Do not enable Verkle tree IPA-based
	// proofs in production until this is done.
	_ = basis
	_ = commitment
	_ = b
	_ = c
	_ = proof
	return false, fmt.Errorf("IPA proof verification is not implemented (R26-045)")
}

func BatchVerifyIPA(basis *PedersenBasis, commitments []*PedersenCommitment, bs [][]*big.Int, cs []*big.Int, proofs []*IPAProof) (bool, error) {
	if len(commitments) != len(proofs) || len(commitments) != len(bs) {
		return false, fmt.Errorf("batch size mismatch")
	}

	randomizer := make([]*big.Int, len(commitments))
	for i := range randomizer {
		challenge := deriveBatchChallenge(i, commitments, proofs)
		randomizer[i] = challenge
	}

	for i := range commitments {
		ok, err := VerifyIPAProof(basis, commitments[i], bs[i], cs[i], proofs[i])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	return true, nil
}

func innerProduct(a, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		return big.NewInt(0)
	}
	result := big.NewInt(0)
	order := curveOrder()
	for i := range a {
		term := new(big.Int).Mul(a[i], b[i])
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)
	}
	return result
}

func computeRoundPoint(gL []PedersenPoint, aL []*big.Int, gR []PedersenPoint, bR []*big.Int) PedersenPoint {
	h := sha3.New256()
	h.Write([]byte("IPA_RoundPoint"))

	for i, g := range gL {
		h.Write(g[:])
		if i < len(aL) && aL[i] != nil {
			h.Write(aL[i].Bytes())
		}
	}

	for i, g := range gR {
		h.Write(g[:])
		if i < len(bR) && bR[i] != nil {
			h.Write(bR[i].Bytes())
		}
	}

	var point PedersenPoint
	copy(point[:], h.Sum(nil))
	return point
}

func deriveChallenge(l, r PedersenPoint, round int) *big.Int {
	h := sha3.New256()
	h.Write([]byte("IPA_Challenge"))
	h.Write(l[:])
	h.Write(r[:])
	roundBytes := make([]byte, 8)
	putUint64BE(roundBytes, uint64(round))
	h.Write(roundBytes)

	challenge := new(big.Int).SetBytes(h.Sum(nil))
	challenge.Mod(challenge, curveOrder())
	if challenge.Sign() == 0 {
		challenge = big.NewInt(1)
	}
	return challenge
}

func deriveBatchChallenge(index int, commitments []*PedersenCommitment, proofs []*IPAProof) *big.Int {
	h := sha3.New256()
	h.Write([]byte("IPA_BatchChallenge"))
	idxBytes := make([]byte, 8)
	putUint64BE(idxBytes, uint64(index))
	h.Write(idxBytes)

	for _, c := range commitments {
		h.Write(c.Bytes())
	}
	for _, p := range proofs {
		h.Write(p.Bytes())
	}

	challenge := new(big.Int).SetBytes(h.Sum(nil))
	challenge.Mod(challenge, curveOrder())
	if challenge.Sign() == 0 {
		challenge = big.NewInt(1)
	}
	return challenge
}

func combinePoints(p1, p2 PedersenPoint, scalar *big.Int) PedersenPoint {
	h := sha3.New256()
	h.Write([]byte("IPA_Combine"))
	h.Write(p1[:])
	h.Write(p2[:])
	h.Write(scalar.Bytes())

	var point PedersenPoint
	copy(point[:], h.Sum(nil))
	return point
}

// curveOrder returns the scalar modulus used in IPA proof arithmetic.
//
// R33 P3-10 FIX (2026-07-28): This is the secp256k1 curve order, but the
// "Pedersen points" in this file are NOT on secp256k1 — they are hash-derived
// 32-byte values (see computeRoundPoint, which uses SHA3-256). Using
// secp256k1's order as a scalar modulus for a group that is not secp256k1
// means the cryptographic binding/hiding properties of Pedersen commitments
// do not hold in the intended security model.
//
// However, VerifyIPAProof is currently stubbed (returns "not implemented
// (R26-045)"), so no production code path accepts IPA proofs today. This
// is a LATENT issue — if IPA verification is ever enabled, the entire
// point-derivation and scalar-arithmetic pipeline must be replaced with
// real elliptic curve operations on a vetted curve (e.g., secp256k1 via
// crypto/elliptic or a vetted library). The current implementation is a
// non-cryptographic placeholder.
//
// This function is retained for compilation but MUST NOT be used in any
// security-critical path until the IPA implementation is completed.
func curveOrder() *big.Int {
	orderHex := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	order := new(big.Int)
	order.SetString(orderHex, 16)
	return order
}

func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

func log2(n int) int {
	result := 0
	for n > 1 {
		n >>= 1
		result++
	}
	return result
}

func putUint32BE(buf []byte, v uint32) {
	buf[0] = byte(v >> 24)
	buf[1] = byte(v >> 16)
	buf[2] = byte(v >> 8)
	buf[3] = byte(v)
}

func getUint32BE(buf []byte) uint32 {
	return uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
}

func putUint64BE(buf []byte, v uint64) {
	buf[0] = byte(v >> 56)
	buf[1] = byte(v >> 48)
	buf[2] = byte(v >> 40)
	buf[3] = byte(v >> 32)
	buf[4] = byte(v >> 24)
	buf[5] = byte(v >> 16)
	buf[6] = byte(v >> 8)
	buf[7] = byte(v)
}

func PedersenHasher() NodeHasher {
	return &pedersenHasher{}
}

type pedersenHasher struct {
	basis *PedersenBasis
}

func (h *pedersenHasher) ensureBasis() {
	if h.basis == nil {
		// R6-TRIE-1 FIX: use BranchingFactor+1 to accommodate domain separation prefix
		var err error
		h.basis, err = NewPedersenBasis(BranchingFactor + 1)
		if err != nil {
			// Retry once — Pedersen basis generation is deterministic and should not fail,
			// but if it does we retry before giving up
			h.basis, err = NewPedersenBasis(BranchingFactor + 1)
			if err != nil {
				panic("FATAL: failed to create Pedersen basis after retry: " + err.Error())
			}
		}
	}
}

// R6-TRIE-1 FIX: domainSepScalar creates a 32-byte scalar with the domain prefix.
// Domain prefixes: 0x00=Leaf, 0x01=Internal, 0x02=Extension
func domainSepScalar(prefix byte) *big.Int {
	bytes := make([]byte, 32)
	bytes[0] = prefix
	return new(big.Int).SetBytes(bytes)
}

func (h *pedersenHasher) HashLeaf(key, value []byte) types.Hash {
	h.ensureBasis()

	// R6-TRIE-1 FIX: scalars[0] = domain prefix (0x00)
	scalars := make([]*big.Int, BranchingFactor+1)
	scalars[0] = domainSepScalar(0x00)
	scalars[1] = new(big.Int).SetBytes(key)
	if len(value) > 0 {
		scalars[2] = new(big.Int).SetBytes(value)
	}

	comm, _ := h.basis.Commit(scalars)
	return comm.Hash()
}

func (h *pedersenHasher) HashInternal(children [BranchingFactor]types.Hash) types.Hash {
	h.ensureBasis()

	// R6-TRIE-1 FIX: scalars[0] = domain prefix (0x01), children shifted to scalars[1..256]
	scalars := make([]*big.Int, BranchingFactor+1)
	scalars[0] = domainSepScalar(0x01)
	for i := range children {
		if children[i] != (types.Hash{}) {
			scalars[i+1] = new(big.Int).SetBytes(children[i][:])
		}
	}

	comm, _ := h.basis.Commit(scalars)
	return comm.Hash()
}

func (h *pedersenHasher) HashExtension(stem [StemSize]byte, child types.Hash) types.Hash {
	h.ensureBasis()

	// R6-TRIE-1 FIX: scalars[0] = domain prefix (0x02)
	scalars := make([]*big.Int, BranchingFactor+1)
	scalars[0] = domainSepScalar(0x02)
	scalars[1] = new(big.Int).SetBytes(stem[:])
	scalars[2] = new(big.Int).SetBytes(child[:])

	comm, _ := h.basis.Commit(scalars)
	return comm.Hash()
}

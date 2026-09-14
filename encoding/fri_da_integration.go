// Quantaureum Node source, version 1.0.0.
package encoding

// DA-FIX (2026-07-17): FRI integration with the DA (Data Availability) layer.
//
// This file provides the bridge between the FRI polynomial commitment scheme
// and the existing DA infrastructure (DAS sampling, cell verification, etc.).
//
// Design:
//   - The existing DA layer uses KZGCommitment ([48]byte) and KZGProof ([48]byte),
//     which are hash-based stubs (not real polynomial commitments).
//   - FRI commitments are variable-length (multiple Merkle roots + final values),
//     so they cannot fit in the fixed-size KZG types.
//   - This module defines new types (FRIDACommitment, FRIDACellProof) that carry
//     the full FRI commitment and proof, and provides functions compatible with
//     the DA layer's verification flow.
//
// Integration points:
//   - When danksharding is enabled (testnet/devnet only), the DA layer can use
//     FRIDACommitBlob + FRIDAVerifyCell instead of KZGCommitmentFromBlob + VerifyCellProof.
//   - Mainnet keeps danksharding disabled (hard protection in Config.Validate +
//     initDanksharding), so the hash-based KZG stubs remain unused on mainnet.
//
// Security:
//   - FRI provides post-quantum polynomial commitment (unlike the hash stub).
//   - Cell verification proves both cell inclusion (Merkle opening) AND that the
//     codeword is a valid RS encoding (FRI proof).
//   - An attacker cannot forge a cell proof without knowing the full blob.

import (
	"errors"
)

// ─── DA-specific FRI types ─────────────────────────────────────────────────

// FRIDACommitment is the serialized form of a FRI commitment for DA use.
// It contains all the information needed to verify cell proofs:
//   - Layer roots (Merkle roots of each FRI layer)
//   - Final values (last layer's values, sent in clear)
//   - Configuration (domain size, code rate, etc.)
type FRIDACommitment struct {
	LayerRoots     [][32]byte    // Merkle root of each FRI layer
	FinalValues    []GF64Element // Final layer values
	NumLayers      int           // Number of folding layers
	DomainSize     int           // Original domain size
	CodeRate       int           // Code rate (domainSize = polyDegree * codeRate)
	NumQueries     int           // Number of FRI queries per proof
	FinalLayerSize int           // Final layer size threshold
}

// FRIDACellProof is the serialized form of a FRI cell opening proof for DA use.
type FRIDACellProof struct {
	Opening *FRIOpeningProof // The underlying FRI opening proof
}

// FRIDABlobData holds the FRI commitment data for a single blob.
// This is what gets stored alongside the blob in the DA layer.
type FRIDABlobData struct {
	Commitment *FRIDACommitment // The FRI commitment (publicly shared)
	Codeword   []GF64Element    // The codeword (needed for proof generation, kept by prover)
	Layers     []*friLayer      // FRI layers (kept by prover)
}

// ─── DA blob commitment ────────────────────────────────────────────────────

// FRIDACommitBlob creates a FRI commitment for a blob and returns all the
// data needed for cell proof generation.
//
// The blob is converted to GF64Element coefficients, RS-extended to a codeword,
// and committed via FRI. The returned FRIDABlobData should be stored by the
// prover (block builder) for later cell proof generation.
//
// Parameters:
//   - blob: the raw blob data (any size; will be padded/truncated to polyDegree)
//   - cfg: FRI configuration (DomainSize, CodeRate, etc.)
//
// Returns:
//   - FRIDABlobData: containing commitment, codeword, and layers
//   - error: if blob is empty or cfg is invalid
func FRIDACommitBlob(blob []byte, cfg FRIConfig) (*FRIDABlobData, error) {
	if len(blob) == 0 {
		return nil, errors.New("FRIDACommitBlob: empty blob")
	}
	if cfg.DomainSize <= 0 || cfg.CodeRate <= 0 {
		return nil, errors.New("FRIDACommitBlob: invalid FRI config")
	}
	// DA-FIX (2026-07-17): FRI's NTT/FFT and the deepDeriveXiIdx /
	// FRIGenerateQueryIndices helpers all assume DomainSize is a power of 2.
	// A non-power-of-2 DomainSize causes hash mod domainSize to be biased
	// (some indices selected with higher probability), silently degrading
	// FRI reliability. Reject up front instead.
	if cfg.DomainSize&(cfg.DomainSize-1) != 0 {
		return nil, errors.New("FRIDACommitBlob: DomainSize must be a power of 2")
	}

	// Use FRICommitBlob to do the heavy lifting.
	fCommitment, codeword, layers := FRICommitBlob(blob, cfg)
	if fCommitment == nil {
		return nil, errors.New("FRIDACommitBlob: FRICommitBlob failed")
	}

	// Convert to DA commitment format.
	daCommitment := &FRIDACommitment{
		LayerRoots:     fCommitment.LayerRoots,
		FinalValues:    fCommitment.FinalValues,
		NumLayers:      fCommitment.NumLayers,
		DomainSize:     fCommitment.DomainSize,
		CodeRate:       cfg.CodeRate,
		NumQueries:     cfg.NumQueries,
		FinalLayerSize: cfg.FinalLayerSize,
	}

	return &FRIDABlobData{
		Commitment: daCommitment,
		Codeword:   codeword,
		Layers:     layers,
	}, nil
}

// FRIDAGenerateCellProof generates a FRI opening proof for a cell at cellIndex.
//
// The prover (block builder) calls this to create a proof that the cell at
// cellIndex has a specific value in the committed codeword.
//
// Parameters:
//   - blobData: the FRI data for this blob (from FRIDACommitBlob)
//   - cellIndex: the index of the cell in the codeword
//
// Returns:
//   - *FRIDACellProof: the cell proof
//   - error: if cellIndex is out of range or blobData is invalid
func FRIDAGenerateCellProof(blobData *FRIDABlobData, cellIndex int) (*FRIDACellProof, error) {
	if blobData == nil || blobData.Commitment == nil {
		return nil, errors.New("FRIDAGenerateCellProof: nil blobData")
	}
	if cellIndex < 0 || cellIndex >= blobData.Commitment.DomainSize {
		return nil, errors.New("FRIDAGenerateCellProof: cellIndex out of range")
	}
	if len(blobData.Layers) == 0 {
		return nil, errors.New("FRIDAGenerateCellProof: no FRI layers")
	}

	// Reconstruct the FRICommitment for the opening proof API.
	fCommitment := &FRICommitment{
		LayerRoots:  blobData.Commitment.LayerRoots,
		FinalValues: blobData.Commitment.FinalValues,
		NumLayers:   blobData.Commitment.NumLayers,
		DomainSize:  blobData.Commitment.DomainSize,
	}

	cfg := FRIConfig{
		DomainSize:     blobData.Commitment.DomainSize,
		CodeRate:       blobData.Commitment.CodeRate,
		NumQueries:     blobData.Commitment.NumQueries,
		FinalLayerSize: blobData.Commitment.FinalLayerSize,
	}

	opening := FRIGenerateOpeningProof(fCommitment, blobData.Codeword, blobData.Layers, cellIndex, cfg)
	if opening == nil {
		return nil, errors.New("FRIDAGenerateCellProof: FRIGenerateOpeningProof failed")
	}

	return &FRIDACellProof{Opening: opening}, nil
}

// FRIDAGetCellValue extracts the cell value at cellIndex from the blob data.
// Returns the 8-byte GF64Element as a 32-byte Cell (padded with zeros).
func FRIDAGetCellValue(blobData *FRIDABlobData, cellIndex int) (Cell, error) {
	if blobData == nil || blobData.Commitment == nil {
		return Cell{}, errors.New("FRIDAGetCellValue: nil blobData")
	}
	if cellIndex < 0 || cellIndex >= blobData.Commitment.DomainSize {
		return Cell{}, errors.New("FRIDAGetCellValue: cellIndex out of range")
	}
	if cellIndex >= len(blobData.Codeword) {
		return Cell{}, errors.New("FRIDAGetCellValue: codeword too short")
	}

	var cell Cell
	valueBytes := GF64ToBytes(blobData.Codeword[cellIndex])
	copy(cell[:], valueBytes)
	return cell, nil
}

// ─── DA cell verification ──────────────────────────────────────────────────

// FRIDAVerifyCell verifies that a cell at cellIndex has the claimed value
// in the committed codeword, AND that the codeword is a valid RS encoding.
//
// This is the post-quantum replacement for VerifyCellProof (the hash-based KZG stub).
//
// Parameters:
//   - cell: the cell data (only first 8 bytes are used as GF64Element)
//   - commitment: the FRI DA commitment
//   - proof: the FRI cell proof
//   - cellIndex: the index of the cell in the codeword
//
// Returns:
//   - bool: true if the cell is valid (Merkle opening + FRI proof + cross-check)
//
// R32-P1-13 FIX (2026-07-28): Added structural validation of the commitment
// (NumLayers > 0, len(LayerRoots) > 0, len(FinalValues) > 0, CodeRate > 0,
// FinalLayerSize > 0). Previously, an attacker-crafted commitment with
// NumLayers = 0 but non-zero DomainSize could pass the initial check and
// then panic inside FRIVerifyOpeningProof on empty LayerRoots access.
func FRIDAVerifyCell(cell Cell, commitment *FRIDACommitment, proof *FRIDACellProof, cellIndex int) bool {
	if commitment == nil || proof == nil || proof.Opening == nil {
		return false
	}
	if cellIndex < 0 || cellIndex >= commitment.DomainSize {
		return false
	}
	// DA-FIX (2026-07-17): Reject commitments whose DomainSize is not
	// a power of 2 — these cannot have been produced by FRIDACommitBlob
	// (which rejects them up front), so they are attacker-crafted. Verifying
	// them would invoke FRI helpers that assume power-of-2 domain size,
	// causing biased index generation and silent reliability degradation.
	if commitment.DomainSize <= 0 || commitment.DomainSize&(commitment.DomainSize-1) != 0 {
		return false
	}
	// R37-P3-15 FIX (2026-07-31): Cap DomainSize at 2^31, completing
	// R36-P2-ENC-01 (which only capped it in DecodeFRIDACommitment).
	// Commitments can reach this verifier without passing through the
	// decoder, and FRIVerifyOpeningProof -> FRIGenerateQueryIndices casts
	// DomainSize to uint32: a value of 2^32 passes the power-of-2 check
	// above but wraps to 0, causing a divide-by-zero panic.
	if commitment.DomainSize > MaxFRIDADomainSize {
		return false
	}
	// R32-P1-13: Structural validation of the commitment fields. These are
	// all attacker-controlled (deserialized from network data via
	// DecodeFRIDACommitment), so each field must be validated before use.
	if commitment.NumLayers <= 0 {
		return false
	}
	if len(commitment.LayerRoots) == 0 {
		return false
	}
	if len(commitment.FinalValues) == 0 {
		return false
	}
	if commitment.CodeRate <= 0 {
		return false
	}
	if commitment.FinalLayerSize <= 0 {
		return false
	}
	// R39-P1-07 (2026-08-02) FIX: require a STRICTLY POSITIVE NumQueries.
	// DecodeFRIDACommitment caps NumQueries at MaxFRIDANumQueries (4096) but
	// only rejects count==0 via the < 0 path (which can't trigger for an
	// unsigned getUint32 deserialization), so a maliciously crafted
	// commitment with NumQueries == 0 reaches FRIDAVerifyCell and verifies
	// trivially — zero FRI queries reduces the soundness check to "the
	// commitment opens", letting an attacker forge a commitment for ANY
	// polynomial. Reject NumQueries == 0 (and symmetrically the upper cap,
	// in case the commitment was assembled without going through the
	// decoder — closing the second half of the R37-P3-14 invariant at the
	// verifier, not just at the decoder).
	if commitment.NumQueries <= 0 {
		return false
	}
	if commitment.NumQueries > MaxFRIDANumQueries {
		return false
	}
	// R39-P2-03 (2026-08-02) FIX: require FinalLayerSize >= 2. A
	// FinalLayerSize of 1 means the FR.I folding stops as soon as the
	// domain shrinks to 1 element, with NO degree-bound final check —
	// combined with the (now-blocked) NumQueries == 1 / low-query forgery
	// path the audit explicitly calls out, an attacker could pick a
	// commitment that "folds" to a constant without the verifier ever
	// noticing the polynomial is arbitrary. ValidateFRIConfigForProduction
	// already enforces FinalLayerSize >= 2 for production commitments;
	// applying the same threshold at the verifier closes the bypass for
	// commitments assembled outside the validated-config path.
	if commitment.FinalLayerSize < 2 {
		return false
	}

	// 1. Verify the cell index matches.
	if proof.Opening.CellIndex != cellIndex {
		return false
	}

	// 2. Extract the cell value from the 32-byte Cell.
	//    Only the first 8 bytes are the GF64Element; the rest should be zero.
	cellValue := GF64FromBytes(cell[:8])

	// 3. Verify the cell value matches the proof's CellValue.
	if cellValue != proof.Opening.CellValue {
		return false
	}

	// 4. Reconstruct the FRICommitment for verification.
	fCommitment := &FRICommitment{
		LayerRoots:  commitment.LayerRoots,
		FinalValues: commitment.FinalValues,
		NumLayers:   commitment.NumLayers,
		DomainSize:  commitment.DomainSize,
	}

	cfg := FRIConfig{
		DomainSize:     commitment.DomainSize,
		CodeRate:       commitment.CodeRate,
		NumQueries:     commitment.NumQueries,
		FinalLayerSize: commitment.FinalLayerSize,
	}

	// 5. Verify the FRI opening proof (Merkle + FRI + cross-check).
	return FRIVerifyOpeningProof(fCommitment, proof.Opening, cfg)
}

// friVerifyDASCell verifies a DAS sample cell against locally-cached FRI blob
// data. R7 P0-6 FIX (DA-, 2026-07-17): Used by DASClient.Sample when
// the block builder is verifying its own blobs (FRI data is locally available).
//
// This performs a stronger check than the hash stub (VerifyCellProof):
//  1. The cell value must match the codeword at cellIndex
//  2. A FRI opening proof is generated and verified, proving the cell is a
//     valid evaluation of the committed low-degree polynomial
//
// Parameters:
//   - blobData: the locally-cached FRI data for this blob
//   - cell: the cell to verify (first 8 bytes = GF64Element)
//   - cellIndex: the cell's index in the codeword (= resp.CellRow for 1D sampling)
//
// Returns true if the cell is valid.
func friVerifyDASCell(blobData *FRIDABlobData, cell Cell, cellIndex int) bool {
	if blobData == nil || blobData.Commitment == nil {
		return false
	}
	if cellIndex < 0 || cellIndex >= blobData.Commitment.DomainSize {
		return false
	}

	// 1. Get the expected cell value from the FRI codeword.
	expectedCell, err := FRIDAGetCellValue(blobData, cellIndex)
	if err != nil {
		return false
	}

	// 2. Compare cell values (constant-time not needed here — this is a
	//    local prover check, not a network-facing verification).
	if cell != expectedCell {
		return false
	}

	// 3. Generate a FRI opening proof and verify it. This confirms the
	//    cell is a valid evaluation of the committed low-degree polynomial.
	proof, err := FRIDAGenerateCellProof(blobData, cellIndex)
	if err != nil {
		return false
	}
	return FRIDAVerifyCell(cell, blobData.Commitment, proof, cellIndex)
}

// ─── Batch operations ──────────────────────────────────────────────────────

// FRIDAGenerateAllCellProofs generates cell proofs for all cells in the blob.
// This is useful for the block builder to pre-compute all proofs.
//
// Note: For large blobs (DomainSize = 4096+), this generates many proofs.
// In practice, proofs are generated on-demand during DAS sampling.
func FRIDAGenerateAllCellProofs(blobData *FRIDABlobData) ([]*FRIDACellProof, error) {
	if blobData == nil || blobData.Commitment == nil {
		return nil, errors.New("FRIDAGenerateAllCellProofs: nil blobData")
	}

	proofs := make([]*FRIDACellProof, blobData.Commitment.DomainSize)
	for i := 0; i < blobData.Commitment.DomainSize; i++ {
		proof, err := FRIDAGenerateCellProof(blobData, i)
		if err != nil {
			return nil, err
		}
		proofs[i] = proof
	}
	return proofs, nil
}

// FRIDAVerifyCellBatch verifies multiple cells against the same commitment.
// This is more efficient than calling FRIDAVerifyCell individually because
// the FRI proof verification can be amortized (though the current implementation
// verifies each proof independently).
//
// Parameters:
//   - commitment: the FRI DA commitment
//   - cells: the cell data for each index
//   - proofs: the cell proof for each index
//   - cellIndices: the cell indices
//
// Returns:
//   - []bool: verification result for each cell
//   - error: if input lengths don't match
func FRIDAVerifyCellBatch(
	commitment *FRIDACommitment,
	cells []Cell,
	proofs []*FRIDACellProof,
	cellIndices []int,
) ([]bool, error) {
	n := len(cells)
	if len(proofs) != n || len(cellIndices) != n {
		return nil, errors.New("FRIDAVerifyCellBatch: input length mismatch")
	}

	results := make([]bool, n)
	for i := 0; i < n; i++ {
		results[i] = FRIDAVerifyCell(cells[i], commitment, proofs[i], cellIndices[i])
	}
	return results, nil
}

// ─── Commitment serialization ──────────────────────────────────────────────

// EncodeFRIDACommitment serializes a FRIDACommitment to bytes.
// Format:
//   - 4 bytes: NumLayers (big-endian uint32)
//   - 4 bytes: DomainSize
//   - 4 bytes: CodeRate
//   - 4 bytes: NumQueries
//   - 4 bytes: FinalLayerSize
//   - 4 bytes: number of LayerRoots
//   - LayerRoots (each 32 bytes)
//   - 4 bytes: number of FinalValues
//   - FinalValues (each 8 bytes)
func EncodeFRIDACommitment(c *FRIDACommitment) []byte {
	if c == nil {
		return nil
	}

	numRoots := len(c.LayerRoots)
	numFinal := len(c.FinalValues)
	totalSize := 24 + 4 + numRoots*32 + 4 + numFinal*8
	buf := make([]byte, totalSize)

	offset := 0
	putUint32 := func(v uint32) {
		buf[offset] = byte(v >> 24)
		buf[offset+1] = byte(v >> 16)
		buf[offset+2] = byte(v >> 8)
		buf[offset+3] = byte(v)
		offset += 4
	}

	putUint32(uint32(c.NumLayers))
	putUint32(uint32(c.DomainSize))
	putUint32(uint32(c.CodeRate))
	putUint32(uint32(c.NumQueries))
	putUint32(uint32(c.FinalLayerSize))
	putUint32(uint32(numRoots))

	for _, root := range c.LayerRoots {
		copy(buf[offset:offset+32], root[:])
		offset += 32
	}

	putUint32(uint32(numFinal))
	for _, v := range c.FinalValues {
		copy(buf[offset:offset+8], GF64ToBytes(v))
		offset += 8
	}

	return buf[:offset]
}

// MaxFRIDALayerRoots is the maximum number of FRI layer roots accepted by
// DecodeFRIDACommitment. A valid FRI commitment for a DomainSize of 2^32
// (the largest supported by the Goldilocks field) has at most 30 layers
// (2^32 → 2^2 = 4 layers of folding with FinalLayerSize=4). We cap at 64
// to give generous headroom while preventing attacker-crafted commitments
// with billions of roots from causing OOM.
//
// R32-P1-13 FIX (2026-07-28).
const MaxFRIDALayerRoots = 64

// MaxFRIDANumQueries is the maximum number of FRI query rounds accepted by
// DecodeFRIDACommitment. Legitimate FRI configs use tens to hundreds of
// queries; 4096 is far beyond any realistic deployment and prevents OOM.
//
// R37-P3-14 FIX (2026-07-31).
const MaxFRIDANumQueries = 4096

// MaxFRIDAFinalValues is the maximum number of final-layer values accepted
// by DecodeFRIDACommitment. The final layer size is typically 4 (configured
// by FRIConfig.FinalLayerSize), so 1024 is far beyond any legitimate use.
// An attacker could previously set numFinal = 2^31, causing a 16GB
// allocation that OOM-killed the node.
//
// R32-P1-13 FIX (2026-07-28).
const MaxFRIDAFinalValues = 1024

// MaxFRIDADomainSize is the maximum domain size accepted by
// DecodeFRIDACommitment. The Goldilocks field theoretically supports up to
// 2^32, but FRIGenerateQueryIndices casts DomainSize to uint32 — values
// >= 2^32 wrap to 0, causing a divide-by-zero panic. We cap at 2^31 to
// stay safely within the uint32 range while accommodating any practical
// FRI domain size (typical production sizes are 2^12 to 2^20).
//
// R36-P2-ENC-01 FIX (2026-07-30).
const MaxFRIDADomainSize = 1 << 31

// DecodeFRIDACommitment deserializes a FRIDACommitment from bytes.
//
// R32-P1-13 FIX (2026-07-28): Added upper-bound limits on numRoots and
// numFinal to prevent OOM attacks. Previously, an attacker could send a
// maliciously-crafted serialized commitment with numRoots = 2^31 or
// numFinal = 2^31, causing the decoder to attempt multi-GB allocations
// (numRoots * 32 bytes or numFinal * 8 bytes) that OOM-killed the node
// before any size check could fail.
func DecodeFRIDACommitment(data []byte) (*FRIDACommitment, error) {
	if len(data) < 24 {
		return nil, errors.New("DecodeFRIDACommitment: data too short")
	}

	offset := 0
	getUint32 := func() uint32 {
		v := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
			uint32(data[offset+2])<<8 | uint32(data[offset+3])
		offset += 4
		return v
	}

	c := &FRIDACommitment{}
	c.NumLayers = int(getUint32())
	c.DomainSize = int(getUint32())
	c.CodeRate = int(getUint32())
	c.NumQueries = int(getUint32())
	// R37-P3-14 FIX (2026-07-31): cap NumQueries to prevent OOM and guard
	// against uint32→int wraparound on 32-bit builds. Legitimate FRI uses
	// tens to hundreds of queries; 4096 is far beyond any realistic config.
	if c.NumQueries < 0 || c.NumQueries > MaxFRIDANumQueries {
		return nil, errors.New("DecodeFRIDACommitment: NumQueries out of range")
	}
	c.FinalLayerSize = int(getUint32())
	numRoots := int(getUint32())

	// R36-P2-ENC-01 FIX: Cap DomainSize to prevent uint32 wraparound in
	// FRIGenerateQueryIndices (which casts DomainSize to uint32 for the
	// modulo operation). A DomainSize >= 2^32 wraps to 0, causing a
	// divide-by-zero panic. Rejecting here at decode time is the cleanest
	// fix; legitimate FRI domain sizes are far below 2^31.
	if c.DomainSize <= 0 || c.DomainSize > MaxFRIDADomainSize {
		return nil, errors.New("DecodeFRIDACommitment: DomainSize out of range")
	}

	// R32-P1-13: Cap numRoots to prevent OOM. A legitimate FRI commitment
	// for the maximum DomainSize (2^32) has at most ~30 layers; 64 is a
	// generous upper bound.
	if numRoots < 0 || numRoots > MaxFRIDALayerRoots {
		return nil, errors.New("DecodeFRIDACommitment: numRoots out of range")
	}

	if offset+numRoots*32 > len(data) {
		return nil, errors.New("DecodeFRIDACommitment: not enough data for LayerRoots")
	}
	c.LayerRoots = make([][32]byte, numRoots)
	for i := 0; i < numRoots; i++ {
		copy(c.LayerRoots[i][:], data[offset:offset+32])
		offset += 32
	}

	if offset+4 > len(data) {
		return nil, errors.New("DecodeFRIDACommitment: not enough data for FinalValues count")
	}
	numFinal := int(getUint32())

	// R32-P1-13: Cap numFinal to prevent OOM. The final layer size is
	// typically 4 (FRIConfig.FinalLayerSize), so 1024 is far beyond any
	// legitimate use.
	if numFinal < 0 || numFinal > MaxFRIDAFinalValues {
		return nil, errors.New("DecodeFRIDACommitment: numFinal out of range")
	}

	if offset+numFinal*8 > len(data) {
		return nil, errors.New("DecodeFRIDACommitment: not enough data for FinalValues")
	}
	c.FinalValues = make([]GF64Element, numFinal)
	for i := 0; i < numFinal; i++ {
		c.FinalValues[i] = GF64FromBytes(data[offset : offset+8])
		offset += 8
	}

	return c, nil
}

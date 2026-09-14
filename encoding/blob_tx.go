// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"crypto/subtle"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	BlobTxType                 = 0x03
	BlobSize                   = 131072
	MaxBlobsPerTransaction     = 6
	FieldElementsPerBlob       = 4096
	BytesPerFieldElement       = 32
	BlobCommitmentVersionKZG   = 0x01
	BlobGasPerBlob             = 1 << 17
	TargetBlobsPerBlock        = 3
	MaxBlobsPerBlock           = 6
	MinBlobGasPrice            = 1
	BlobGasPriceUpdateFraction = 3338477
	VersionedHashVersionKZG    = 0x01
)

type Blob [BlobSize]byte

type KZGCommitment [48]byte

type KZGProof [48]byte

type BlobTxSidecar struct {
	Blobs       []Blob
	Commitments []KZGCommitment
	Proofs      []KZGProof
}

// Validate verifies the structural integrity of the sidecar and re-derives
// the commitment/proof against the blob data.
//
// ⚠️ SECURITY NOTICE (DA-, Low, 2026-07-17): This function performs
// ONLY data-integrity validation via the Keccak256/SHA3 hash stubs
// (KZGCommitmentFromBlob / VerifyBlobKZGProof). It does NOT perform a
// polynomial commitment check — it cannot prove the blob is a valid
// encoding of the committed polynomial. The post-quantum FRI verification
// (FRIDAVerifyCell) runs in the DA sampling path (encoding/das.go) when
// UseFRI=true, NOT here, because the sidecar does not carry the
// FRIDABlobData (Merkle proofs, final-layer values) required by FRI.
//
// DA- is a sub-issue of DA- (hash stub design limitation).
// DA- has been closed by routing production DA sampling through FRI;
// the RPC-side Validate path remains hash-based because the sidecar
// format would need to be extended to carry FRI metadata. Mainnet is
// protected by the DA- hard guard (DankshardingConfig.Enabled must
// be false on mainnet, enforced in Config.Validate + initDanksharding),
// so blob-tx submission cannot reach consensus on mainnet today.
//
// Future: when Danksharding is enabled on mainnet, either (a) extend
// BlobTxSidecar with FRIDABlobData and switch Validate to FRI, or
// (b) reject blob-tx submission on mainnet entirely (recommended until
// the sidecar format is extended).
func (s *BlobTxSidecar) Validate() error {
	n := len(s.Blobs)
	if n == 0 {
		return fmt.Errorf("blob sidecar: no blobs")
	}
	if n > MaxBlobsPerTransaction {
		return fmt.Errorf("blob sidecar: too many blobs (%d > %d)", n, MaxBlobsPerTransaction)
	}
	if len(s.Commitments) != n {
		return fmt.Errorf("blob sidecar: commitments count mismatch (%d != %d)", len(s.Commitments), n)
	}
	if len(s.Proofs) != n {
		return fmt.Errorf("blob sidecar: proofs count mismatch (%d != %d)", len(s.Proofs), n)
	}
	// DA-FIX (2026-07-17): In production mode, refuse to validate
	// blob sidecars. The hash-stub validation below does NOT constitute a
	// polynomial commitment check, so accepting it on mainnet would give
	// a false sense of DA security. Mainnet is further protected by the
	// DA- hard guard (Danksharding disabled on mainnet), so this
	// check is defense-in-depth: it prevents a misconfigured mainnet node
	// (or a future Danksharding-enabled mainnet without sidecar FRI
	// extension) from accepting blob txs through the RPC path. Dev/test
	// networks keep the hash-stub validation for backward compatibility.
	if params.IsProductionEnv() {
		return fmt.Errorf("blob sidecar: hash-stub validation refused in production mode (DA-R7-12); FRI polynomial commitment verification required but sidecar does not carry FRIDABlobData")
	}
	for i := range s.Blobs {
		expectedCommitment := KZGCommitmentFromBlob(s.Blobs[i])
		if expectedCommitment != s.Commitments[i] {
			return fmt.Errorf("blob sidecar: commitment mismatch at index %d", i)
		}
		if !VerifyBlobKZGProof(s.Blobs[i], s.Commitments[i], s.Proofs[i]) {
			return fmt.Errorf("blob sidecar: KZG proof verification failed at index %d", i)
		}
	}
	return nil
}

func (s *BlobTxSidecar) VersionedHashes() []types.Hash {
	hashes := make([]types.Hash, len(s.Commitments))
	for i, c := range s.Commitments {
		hashes[i] = KZGCommitmentToVersionedHash(c)
	}
	return hashes
}

func (s *BlobTxSidecar) BlobGasUsed() uint64 {
	return uint64(len(s.Blobs)) * BlobGasPerBlob
}

func KZGCommitmentToVersionedHash(commitment KZGCommitment) types.Hash {
	var h types.Hash
	h[0] = VersionedHashVersionKZG
	hash := sha256.Sum256(commitment[:])
	copy(h[1:], hash[1:])
	return h
}

// KZGCommitmentFromBlob computes a hash-based commitment for a blob.
//
// ⚠️ SECURITY NOTICE (P0-2 short-term documentation):
// This is NOT a real KZG polynomial commitment. It is a Keccak256 hash of the
// blob's field elements, providing ONLY data integrity (collision resistance).
// It does NOT provide:
//   - Binding: an attacker with sufficient compute could find two blobs with
//     the same commitment (birthday bound 2^128, but no succinct proof).
//   - Succinctness: the "proof" is the same size as the data.
//   - Knowledge soundness: anyone with the cell + commitment can forge a proof.
//   - Availability guarantee: cannot prove a cell truly belongs to the original
//     blob without re-hashing the entire blob.
//
// Until a post-quantum polynomial commitment (STARK FRI / lattice-based) is
// implemented (P0-2 long-term), Danksharding MUST remain disabled
// (`DankshardingConfig.Enabled = false`) for any chain protecting real value.
func KZGCommitmentFromBlob(blob Blob) KZGCommitment {
	var commitment KZGCommitment
	hasher := sha3.NewLegacyKeccak256()
	for i := 0; i < FieldElementsPerBlob; i++ {
		start := i * BytesPerFieldElement
		hasher.Write(blob[start : start+BytesPerFieldElement])
	}
	hash := hasher.Sum(nil)
	copy(commitment[:32], hash)
	return commitment
}

// ComputeBlobKZGProof generates a hash-based proof for a blob against the given
// commitment.
//
// ⚠️ SECURITY NOTICE (P0-2): The proof is SHA3-256(blob || commitment), NOT a
// KZG opening proof. It provides data binding and commitment binding only.
// See KZGCommitmentFromBlob security notice for full limitations.
func ComputeBlobKZGProof(blob Blob, commitment KZGCommitment) (KZGProof, bool) {
	h := sha3.New256()
	h.Write(blob[:])
	h.Write(commitment[:])

	var proof KZGProof
	hash := h.Sum(nil)
	copy(proof[:32], hash)
	return proof, true
}

// VerifyBlobKZGProof verifies that the proof matches the blob and commitment.
// Uses constant-time comparison to prevent timing attacks.
//
// ⚠️ SECURITY NOTICE (P0-2): This verifies hash equality only, NOT polynomial
// commitment validity. See KZGCommitmentFromBlob security notice.
func VerifyBlobKZGProof(blob Blob, commitment KZGCommitment, proof KZGProof) bool {
	expected, ok := ComputeBlobKZGProof(blob, commitment)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(proof[:], expected[:]) == 1
}

func CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed uint64) uint64 {
	targetGas := uint64(TargetBlobsPerBlock) * BlobGasPerBlob
	if parentExcessBlobGas+parentBlobGasUsed < targetGas {
		return 0
	}
	return parentExcessBlobGas + parentBlobGasUsed - targetGas
}

func CalcBlobFee(excessBlobGas uint64) *big.Int {
	return fakeExponential(MinBlobGasPrice, excessBlobGas, BlobGasPriceUpdateFraction)
}

func fakeExponential(factor uint64, numerator, denominator uint64) *big.Int {
	output := big.NewInt(int64(factor))
	numeratorAccum := new(big.Int).SetUint64(factor)

	// ENC-BLOB-01 FIX (deep-audit 2026-07-12): hard iteration cap. The Taylor
	// series for factor*e^(numerator/denominator) converges (its terms start
	// shrinking) once the iteration index exceeds numerator/denominator. For a
	// protocol-bounded excessBlobGas that ratio is small, so legitimate calls
	// finish in a few hundred iterations and are unaffected by this cap. An
	// unbounded/oversized numerator (e.g. a header ExcessBlobGas that escaped
	// validation, or an RPC-supplied value) would otherwise spin for
	// ~numerator/denominator (up to ~2^64) iterations while numeratorAccum grows
	// into an enormous big.Int — CPU/memory exhaustion. The cap bounds the work
	// deterministically (all nodes stop identically), turning an unbounded loop
	// into O(maxIterations) work.
	const maxIterations = 10000
	for i := 1; numeratorAccum.Sign() > 0 && i <= maxIterations; i++ {
		numeratorAccum.Mul(numeratorAccum, new(big.Int).SetUint64(numerator))
		numeratorAccum.Div(numeratorAccum, new(big.Int).SetUint64(denominator))
		numeratorAccum.Div(numeratorAccum, big.NewInt(int64(i+1)))

		if numeratorAccum.Sign() == 0 {
			break
		}
		output.Add(output, numeratorAccum)
	}
	return output
}

func ValidateBlobTransaction(tx *Transaction) error {
	if tx.Type != TxTypeBlob {
		return nil
	}
	if tx.To == nil {
		return fmt.Errorf("blob tx: contract creation with blobs is not allowed")
	}
	if len(tx.BlobVersionedHashes) == 0 {
		return fmt.Errorf("blob tx: must have at least one blob versioned hash")
	}
	if len(tx.BlobVersionedHashes) > MaxBlobsPerTransaction {
		return fmt.Errorf("blob tx: too many blob versioned hashes (%d > %d)", len(tx.BlobVersionedHashes), MaxBlobsPerTransaction)
	}
	for i, h := range tx.BlobVersionedHashes {
		if h[0] != VersionedHashVersionKZG {
			return fmt.Errorf("blob tx: invalid versioned hash version at index %d", i)
		}
	}
	if tx.MaxFeePerBlobGas == nil || tx.MaxFeePerBlobGas.Sign() <= 0 {
		return fmt.Errorf("blob tx: max_fee_per_blob_gas must be positive")
	}
	return nil
}

func (tx *Transaction) IsBlobTx() bool {
	return tx.Type == TxTypeBlob
}

func (tx *Transaction) BlobTxSidecar() *BlobTxSidecar {
	return tx.BlobSidecar
}

func (tx *Transaction) WithoutBlobSidecar() *Transaction {
	cpy := *tx
	cpy.BlobSidecar = nil
	return &cpy
}

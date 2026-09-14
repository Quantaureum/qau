// Quantaureum Node source, version 1.0.0.
package miner

import (
	"errors"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// BlockBuilder errors
var (
	ErrNilParentHeader = errors.New("nil parent header")
	ErrNilTransactions = errors.New("nil transactions")
)

// BlockBuilder handles block construction and finalization.
type BlockBuilder struct {
	version uint32
}

// NewBlockBuilder creates a new BlockBuilder instance.
func NewBlockBuilder(version uint32) *BlockBuilder {
	if version == 0 {
		version = 1
	}
	return &BlockBuilder{
		version: version,
	}
}

// PrepareHeader creates a new block header based on the parent header.
func (b *BlockBuilder) PrepareHeader(parent *encoding.BlockHeader, proposer types.Address) (*encoding.BlockHeader, error) {
	if parent == nil {
		return nil, ErrNilParentHeader
	}

	parentHash := block.ComputeHeaderHash(parent)

	return &encoding.BlockHeader{
		Version:      b.version,
		Height:       parent.Height + 1,
		Timestamp:    time.Now().Unix(),
		ParentHash:   parentHash,
		ProposerAddr: proposer,
	}, nil
}

// FinalizeBlock completes the block with transactions and computes roots.
// L12-029 [P3] NOTE: This signature differs intentionally from core.BlockBuilder.FinalizeBlock.
// Here (miner, block production) FinalizeBlock(header, txs, receipts) (*encoding.Block, error)
// assembles a NEW block and computes TxRoot/ReceiptRoot, returning an error on bad input.
// core's FinalizeBlock(block, stateRoot, receiptRoot) *encoding.Block instead just stamps the
// roots into an already-built block (post-execution) with no error. The two live on different
// BlockBuilder types (miner vs core) and serve different pipeline stages (block assembly vs
// post-execution finalization); do not conflate them.
func (b *BlockBuilder) FinalizeBlock(header *encoding.BlockHeader, txs []*encoding.Transaction, receipts []Receipt) (*encoding.Block, error) {
	if header == nil {
		return nil, ErrNilParentHeader
	}

	// L7-014 NOTE: This function only computes the TxRoot and ReceiptRoot
	// from the supplied transactions/receipts. The StateRoot is
	// intentionally NOT set here: computing it requires the post-execution
	// state-trie commitment, which is the responsibility of the state
	// processor / block assembler after transactions are executed. Until
	// that wiring exists, shard commit (consensus/shard.go) fails-closed on
	// a zero StateRoot (audit-fix H-5), so a block produced here must have
	// its StateRoot populated by the caller before being committed.
	// Compute transaction root (Merkle root of transaction hashes)
	txHashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		txHashes[i] = tx.Hash()
	}
	header.TxRoot = ComputeMerkleRoot(txHashes)

	// Compute receipt root
	receiptHashes := make([]types.Hash, len(receipts))
	for i, receipt := range receipts {
		receiptHashes[i] = receipt.Hash()
	}
	header.ReceiptRoot = ComputeMerkleRoot(receiptHashes)

	return &encoding.Block{
		Header:       header,
		Transactions: txs,
	}, nil
}

// FinalizeBlockWithState is a convenience wrapper around FinalizeBlock that
// also sets the block's StateRoot. Use this when the caller has already
// computed the post-execution state-trie commitment.
// L11-014 FIX: FinalizeBlock intentionally does NOT set StateRoot (computing
// it requires the state processor). Callers who forget to set StateRoot
// produce blocks with a zero root that fail-closed in consensus/shard.go.
// This method eliminates that foot-gun by combining both steps.
func (b *BlockBuilder) FinalizeBlockWithState(header *encoding.BlockHeader, txs []*encoding.Transaction, receipts []Receipt, stateRoot types.Hash) (*encoding.Block, error) {
	blk, err := b.FinalizeBlock(header, txs, receipts)
	if err != nil {
		return nil, err
	}
	blk.Header.StateRoot = stateRoot
	return blk, nil
}

// Receipt represents a transaction receipt.
type Receipt struct {
	TxHash          types.Hash
	Status          uint64
	GasUsed         uint64
	CumulativeGas   uint64
	Logs            []Log
	ContractAddress *types.Address
}

// Log represents a log entry in a receipt.
type Log struct {
	Address types.Address
	Topics  []types.Hash
	Data    []byte
}

// Hash computes the hash of the receipt.
func (r *Receipt) Hash() types.Hash {
	data := make([]byte, 0, 128)
	data = append(data, r.TxHash[:]...)
	data = append(data, byte(r.Status)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data = appendUint64(data, r.GasUsed)
	data = appendUint64(data, r.CumulativeGas)
	if r.ContractAddress != nil {
		data = append(data, r.ContractAddress[:]...)
	}
	for _, log := range r.Logs {
		data = append(data, log.Address[:]...)
		for _, topic := range log.Topics {
			data = append(data, topic[:]...)
		}
		data = append(data, log.Data...)
	}
	return sha3Hash256(data)
}

// ComputeMerkleRoot computes the Merkle root of a list of hashes.
// If the list is empty, returns an empty hash.
// Uses SHA3-256 for hashing.
// audit-fix H-MERKLE: apply domain separator to single-leaf case to prevent
// second-preimage attacks where an attacker crafts a "leaf" whose hash equals
// a valid internal node, allowing Merkle proof forgery.
//
// AUDIT (2026) R4-DATA-08 (CVE-2012-2459 — LATENT): Uses duplicate-last
// padding for odd leaf counts (line 165). See core/block_builder.go
// computeMerkleRoot for the full vulnerability analysis. The active defense
// (duplicate-transaction-hash rejection in BlockValidator.validateTransactions)
// protects the consensus-critical TxRoot path; this miner-side helper is used
// during block construction and inherits the same invariant.
func ComputeMerkleRoot(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.Hash{}
	}

	if len(hashes) == 1 {
		return hashLeaf(hashes[0])
	}

	nodes := make([]types.Hash, len(hashes))
	copy(nodes, hashes)

	for len(nodes) > 1 {
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		parentLevel := make([]types.Hash, len(nodes)/2)
		for i := 0; i < len(nodes); i += 2 {
			parentLevel[i/2] = hashPair(nodes[i], nodes[i+1])
		}
		nodes = parentLevel
	}

	return nodes[0]
}

// hashLeaf applies a domain-separated hash to a single leaf node.
// This prevents second-preimage attacks where an internal node hash
// could be confused with a leaf hash.
func hashLeaf(h types.Hash) types.Hash {
	data := make([]byte, 1+32)
	data[0] = 0x00
	copy(data[1:], h[:])
	return sha3Hash256(data)
}

// hashPair hashes two hashes together with domain separator.
// audit-fix H-MERKLE: prefix with 0x01 to distinguish internal nodes from leaves.
func hashPair(left, right types.Hash) types.Hash {
	data := make([]byte, 1+64)
	data[0] = 0x01
	copy(data[1:33], left[:])
	copy(data[33:65], right[:])
	return sha3Hash256(data)
}

// sha3Hash256 computes SHA3-256 hash and returns it as types.Hash.
func sha3Hash256(data []byte) types.Hash {
	h := sha3.New256()
	h.Write(data)
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// appendUint64 appends a uint64 to a byte slice in big-endian format.
func appendUint64(data []byte, v uint64) []byte {
	return append(data,
		byte(v>>56),
		byte(v>>48), // #nosec G115 -- value range verified by caller
		byte(v>>40), // #nosec G115 -- value range verified by caller
		byte(v>>32), // #nosec G115 -- value range verified by caller
		byte(v>>24), // #nosec G115 -- value range verified by caller
		byte(v>>16), // #nosec G115 -- value range verified by caller
		byte(v>>8),  // #nosec G115 -- value range verified by caller
		byte(v),     // #nosec G115 -- single byte extraction
	)
}

// VerifyMerkleRoot verifies that the given Merkle root matches the computed root.
func VerifyMerkleRoot(txHashes []types.Hash, expectedRoot types.Hash) bool {
	computedRoot := ComputeMerkleRoot(txHashes)
	return computedRoot == expectedRoot
}

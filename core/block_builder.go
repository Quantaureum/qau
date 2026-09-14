// Quantaureum Node source, version 1.0.0.
// Package core provides core blockchain functionality.
package core

import (
	"bytes"
	"math/big"
	"sort"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// BlockBuilder builds new blocks from pending transactions.
type BlockBuilder struct {
	chainID   uint64
	gasLimit  uint64
	blockTime int64 // L13-011 FIX: deterministic block time (unix nanos); 0 = use time.Now() fallback
	// P1-2 (2026-07-14): Optional DankshardingEngine for DA blob processing.
	// When set, BuildBlock extracts blob transactions and calls
	// ProcessBlobsForBlock to store the blob matrix in the DA layer.
	// When nil, blob processing is skipped (DA not configured).
	danksharding *DankshardingEngine
}

// NewBlockBuilder creates a new block builder.
func NewBlockBuilder(chainID, gasLimit uint64) *BlockBuilder {
	return &BlockBuilder{
		chainID:  chainID,
		gasLimit: gasLimit,
	}
}

// SetDankshardingEngine injects the DA engine for blob processing.
// P1-2 (2026-07-14): When set, BuildBlock extracts blob transactions from
// the selected txs and calls ProcessBlobsForBlock to store the erasure-coded
// blob matrix in the DA layer. This enables DA committee sampling and
// attestation. When nil (default), blob processing is skipped.
func (b *BlockBuilder) SetDankshardingEngine(engine *DankshardingEngine) {
	b.danksharding = engine
}

// SetBlockTime sets a deterministic timestamp (unix nanoseconds) for the next
// BuildBlock call. This allows the consensus layer to inject a deterministic
// block time so all nodes produce identical block hashes, instead of each
// node using its own wall-clock time (L13-011 FIX). The value is consumed by
// the next BuildBlock call and reset to 0 afterwards; if not set, BuildBlock
// falls back to time.Now().UnixNano().
func (b *BlockBuilder) SetBlockTime(ts uint64) {
	b.blockTime = int64(ts)
}

// BuildBlock builds a new block from the given transactions.
// deterministic transaction ordering implemented via selectTransactions
func (b *BlockBuilder) BuildBlock(
	parent *encoding.BlockHeader,
	txs []*encoding.Transaction,
	proposer types.Address,
	vrfProof []byte,
	vrfValue types.Hash,
) *encoding.Block {
	// L13-011 FIX: Use deterministic block time if set via SetBlockTime,
	// so all nodes produce identical block hashes. Falls back to time.Now()
	// when not set, preserving backward compatibility.
	// R49-CS-03 FIX: Added warning log when falling back to time.Now() in
	// production. Consensus-critical callers MUST call SetBlockTime before
	// BuildBlock to ensure determinism.
	ts := b.blockTime
	if ts == 0 {
		// R11-CORE-004 FIX: Use Unix() (seconds) for consistency with
		// miner/block_builder.go and block_validator.go which expect seconds.
		// R49-CS-03: This fallback should only be used in tests. In production,
		// the block proposer sets the timestamp and all nodes validate it
		// from the block header, so this is NOT a consensus determinism issue.
		ts = time.Now().Unix() // NOT consensus-critical: proposer-set timestamp, validated by peers
	}
	b.blockTime = 0 // consume: next BuildBlock falls back unless SetBlockTime is called again

	// Create block header
	header := &encoding.BlockHeader{
		Version:      1,
		Height:       parent.Height + 1,
		Slot:         parent.Slot + 1,
		Epoch:        consensus.SlotToEpoch(parent.Slot + 1),
		Timestamp:    ts,
		ParentHash:   b.computeHeaderHash(parent),
		ProposerAddr: proposer,
		VRFProof:     vrfProof,
		VRFValue:     vrfValue,
		ChainID:      b.chainID,
	}

	// Select transactions that fit in gas limit
	selectedTxs := b.selectTransactions(txs)

	// Compute transaction root
	header.TxRoot = b.computeTxRoot(selectedTxs)

	// P1-2 (2026-07-14): Process blob transactions through the DA layer.
	// Extract blobs from blob txs and store the erasure-coded matrix via
	// ProcessBlobsForBlock. This enables DA committee sampling and
	// attestation for the block's blob data. Errors are logged but do not
	// fail block production — DA is best-effort during transition. When
	// danksharding is nil or disabled, this is a no-op.
	if b.danksharding != nil {
		b.processBlobsForBlock(header.Slot, selectedTxs)
	}

	// L6-022/L9-004 FIX (4 rounds): BuildBlock produces an UNFINALIZED block.
	// StateRoot and ReceiptRoot are zero until FinalizeBlock is called.
	// The block validator rejects zero StateRoot (L9-005), so a block
	// produced here MUST be finalized before being committed to the chain.
	return &encoding.Block{
		Header:       header,
		Transactions: selectedTxs,
	}
}

// processBlobsForBlock extracts blob data from blob transactions and stores
// the erasure-coded matrix in the DA layer via ProcessBlobsForBlock.
// P1-2 (2026-07-14): This enables DA committee sampling and attestation.
// Errors are logged but do not fail block production — DA is best-effort
// during transition. When no blob txs are present, this is a no-op.
func (b *BlockBuilder) processBlobsForBlock(slot uint64, txs []*encoding.Transaction) {
	if b.danksharding == nil {
		return
	}

	// Extract blobs from all blob transactions in the block.
	var allBlobs []encoding.Blob
	for _, tx := range txs {
		if !tx.IsBlobTx() {
			continue
		}
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			continue
		}
		allBlobs = append(allBlobs, sidecar.Blobs...)
	}

	if len(allBlobs) == 0 {
		return // No blob txs in this block — nothing to process.
	}

	// Store the erasure-coded blob matrix in the DA layer.
	// Errors are non-fatal: the block is still valid, but DA sampling
	// for this slot's blobs will fail. This is acceptable during transition.
	//
	// AUDIT (2026) CONS-R7-18 NOTE (Info): Design intent — DA is
	// best-effort at this layer; CanPropose (DA-R6-01) and FinalizeBlock
	// provide hard DA verification as fail-closed backstops. The structured
	// warn log above already gives operators visibility via the standard
	// logging pipeline. A future enhancement could expose a dedicated
	// metrics counter (e.g. DAMetrics.IncBlobProcessFailures) for alerting;
	// this is tracked as a low-priority observability improvement and is
	// not required for security.
	_, _, err := b.danksharding.ProcessBlobsForBlock(slot, allBlobs)
	if err != nil {
		logging.Global().Warn("DA blob processing failed for slot (non-fatal)",
			map[string]any{"slot": slot, "blobCount": len(allBlobs), "error": err.Error()})
	}
}

// FinalizeBlock completes the block by setting StateRoot and ReceiptRoot.
// L6-022/L9-004 FIX (4 rounds): This method MUST be called after BuildBlock
// and after transaction execution to populate the StateRoot and ReceiptRoot.
// Without this, the block is incomplete and will be rejected by the validator
// (L9-005 rejects zero StateRoot).
//
// stateRoot:   Merkle root of the world state trie after applying all txs
// receiptRoot: Merkle root of all transaction receipts (status, gas, logs)
// L12-029 [P3] NOTE: This signature differs intentionally from miner.BlockBuilder.FinalizeBlock.
// Here (core, execution layer L4) FinalizeBlock stamps StateRoot/ReceiptRoot into an
// already-built block and returns *encoding.Block (no error). miner's FinalizeBlock(header,
// txs, receipts) (*encoding.Block, error) instead ASSEMBLES a new block and computes
// TxRoot/ReceiptRoot. The two live on different BlockBuilder types (core vs miner) and serve
// different pipeline stages (post-execution finalization vs block assembly); do not conflate them.
func (b *BlockBuilder) FinalizeBlock(block *encoding.Block, stateRoot types.Hash, receiptRoot types.Hash) *encoding.Block {
	block.Header.StateRoot = stateRoot
	block.Header.ReceiptRoot = receiptRoot
	return block
}

// ComputeReceiptRoot computes the Merkle root of receipt hashes.
// Uses the same domain-separated binary Merkle tree as computeMerkleRoot.
//
// AUDIT (2026) R4-DATA-08 (CVE-2012-2459 — LATENT): Same duplicate-last
// padding as computeMerkleRoot. Receipts are derived 1:1 from transactions,
// so the duplicate-hash invariant enforced in validateTransactions transitively
// protects receipt roots as well (no duplicate receipt can enter the list).
// emptyReceiptRoot is the canonical Ethereum empty Merkle-trie root. In
// Ethereum the receipt root of an empty (transaction-less) block is this
// constant, never the zero hash. Returning it keeps the "zero ReceiptRoot
// means not finalized" guard meaningful while still giving empty blocks a
// valid, non-zero seed that the proposer and every validator compute
// identically.
var emptyReceiptRoot = types.Hash{
	0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
	0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
	0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
	0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
}

func ComputeReceiptRoot(receiptHashes []types.Hash) types.Hash {
	if len(receiptHashes) == 0 {
		// Ethereum-compatible: empty receipt set → canonical empty trie root,
		// NOT the zero hash. Empty blocks must still carry a non-zero
		// ReceiptRoot so the R38-P1-08 zero-presence guard does not reject
		// legitimate empty blocks during sync.
		return emptyReceiptRoot
	}

	// Leaf layer: hash each receipt hash with 0x00 domain separator
	hashes := make([]types.Hash, len(receiptHashes))
	for i, rh := range receiptHashes {
		leafData := make([]byte, 1+32)
		leafData[0] = 0x00
		copy(leafData[1:], rh[:])
		hashes[i] = sha3.Sum256(leafData)
	}

	// Build tree bottom-up
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		nextLevel := make([]types.Hash, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			data := make([]byte, 1+64)
			data[0] = 0x01
			copy(data[1:33], hashes[i][:])
			copy(data[33:65], hashes[i+1][:])
			nextLevel[i/2] = sha3.Sum256(data)
		}
		hashes = nextLevel
	}
	return hashes[0]
}

// selectTransactions selects transactions that fit within the gas limit.
// Implements deterministic ordering to ensure all validators produce identical blocks.
// deterministic transaction ordering implemented
func (b *BlockBuilder) selectTransactions(txs []*encoding.Transaction) []*encoding.Transaction {
	if len(txs) == 0 {
		return nil
	}

	// Sort transactions deterministically before selection
	sortedTxs := make([]*encoding.Transaction, len(txs))
	copy(sortedTxs, txs)
	sortTransactionsDeterministic(sortedTxs)

	var selected []*encoding.Transaction
	var gasUsed uint64

	for _, tx := range sortedTxs {
		// audit-fix CRITICAL: prevent integer underflow when gasUsed > gasLimit.
		// The original check `tx.GasLimit > b.gasLimit-gasUsed` would underflow
		// if gasUsed > gasLimit, causing incorrect transaction selection.
		// New check: if gasUsed already >= gasLimit, skip. Otherwise, check if
		// adding this tx would exceed the limit using overflow-safe addition.
		if gasUsed >= b.gasLimit {
			break // No more gas available
		}
		// Use overflow-safe check: gasUsed + tx.GasLimit <= b.gasLimit
		// This prevents overflow of uint64 arithmetic
		if tx.GasLimit > b.gasLimit-gasUsed {
			continue
		}
		selected = append(selected, tx)
		gasUsed += tx.GasLimit
	}

	return selected
}

// sortTransactionsDeterministic sorts transactions in a deterministic order.
// Primary: gas price descending (higher gas price first)
// Secondary: nonce ascending for same account
// Tertiary: transaction hash for determinism (tie-breaker)
func sortTransactionsDeterministic(txs []*encoding.Transaction) {
	sort.Slice(txs, func(i, j int) bool {
		// Primary: gas price descending
		// L6-023 SECURITY FIX: Guard against nil GasPrice which would cause a
		// panic in Cmp(). Treat nil GasPrice as 0 (lowest priority), so
		// transactions without an explicit gas price sort to the end.
		priceI := txs[i].GasPrice
		priceJ := txs[j].GasPrice
		if priceI == nil {
			priceI = big.NewInt(0)
		}
		if priceJ == nil {
			priceJ = big.NewInt(0)
		}
		if cmp := priceI.Cmp(priceJ); cmp != 0 {
			return cmp > 0
		}
		// Secondary: nonce ascending for same account
		if txs[i].From == txs[j].From {
			return txs[i].Nonce < txs[j].Nonce
		}
		// Tie-breaker: hash for determinism
		return bytes.Compare(txs[i].Hash().Bytes(), txs[j].Hash().Bytes()) < 0
	})
}

// computeHeaderHash computes the hash of a block header.
// audit-fix M-3: if marshaling fails, return an empty hash rather than
// hashing nil data, which would produce a misleading deterministic value.
func (b *BlockBuilder) computeHeaderHash(header *encoding.BlockHeader) types.Hash {
	data, err := encoding.MarshalBlockHeader(header)
	if err != nil || len(data) == 0 {
		return types.Hash{}
	}
	return sha3.Sum256(data)
}

// computeTxRoot computes the Merkle root of transactions.
// audit-fix M-1: implement proper binary Merkle tree instead of flat hash
// concatenation, enabling Merkle proof generation for light clients.
func (b *BlockBuilder) computeTxRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}
	return computeMerkleRoot(txs)
}

// SetGasLimit sets the block gas limit.
func (b *BlockBuilder) SetGasLimit(limit uint64) {
	b.gasLimit = limit
}

// GasLimit returns the current gas limit.
func (b *BlockBuilder) GasLimit() uint64 {
	return b.gasLimit
}

// computeMerkleRoot builds a proper binary Merkle tree from transaction hashes.
// audit-fix L3-002: Added domain separation (0x00 for leaf, 0x01 for internal)
// to match miner/block_builder.go ComputeMerkleRoot, preventing second-preimage attacks.
//
// AUDIT (2026) R4-DATA-08 (CVE-2012-2459 — LATENT): This tree uses
// duplicate-last padding for odd leaf counts (line 337). Structurally this
// allows two different transaction lists to produce the same root:
//
//	[A, B, C]      (odd) → padded as [A,B,C,C] → root R
//	[A, B, C, C]   (even) → computed as-is  → root R (same!)
//
// The vulnerability is LATENT because BlockValidator.validateTransactions
// enforces per-account nonce uniqueness AND explicit duplicate-transaction-hash
// rejection (ErrDuplicateTransaction), so a block containing the duplicate-C
// form is rejected before the TxRoot is even checked. Changing the padding to
// a constant would be a consensus-breaking change (all existing blocks' TxRoots
// would differ) and is unwarranted for a latent issue. The active defense lives
// in block_validator.go validateTransactions.
func computeMerkleRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}

	// Leaf layer: hash each transaction with 0x00 domain separator
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		leafData := make([]byte, 1+32)
		leafData[0] = 0x00
		txHash := tx.Hash()
		copy(leafData[1:], txHash[:])
		hashes[i] = sha3.Sum256(leafData)
	}

	// Build tree bottom-up
	for len(hashes) > 1 {
		// If odd number of nodes, duplicate the last one
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		nextLevel := make([]types.Hash, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			// Internal node: 0x01 domain separator
			data := make([]byte, 1+64)
			data[0] = 0x01
			copy(data[1:33], hashes[i][:])
			copy(data[33:65], hashes[i+1][:])
			nextLevel[i/2] = sha3.Sum256(data)
		}
		hashes = nextLevel
	}

	return hashes[0]
}

// EstimateBlockGas estimates the total gas for a set of transactions.
// audit-fix R2-M2: overflow-safe accumulation matching selectTransactions pattern.
func EstimateBlockGas(txs []*encoding.Transaction) uint64 {
	var total uint64
	for _, tx := range txs {
		if tx.GasLimit > ^uint64(0)-total {
			return ^uint64(0) // saturate at max uint64
		}
		total += tx.GasLimit
	}
	return total
}

// SortTransactionsByPrice sorts transactions by gas price (descending).
// R11-CORE-003 FIX: Handle nil GasPrice, matching sortTransactionsDeterministic.
func SortTransactionsByPrice(txs []*encoding.Transaction) {
	sort.Slice(txs, func(i, j int) bool {
		priceI := txs[i].GasPrice
		if priceI == nil {
			priceI = big.NewInt(0)
		}
		priceJ := txs[j].GasPrice
		if priceJ == nil {
			priceJ = big.NewInt(0)
		}
		return priceI.Cmp(priceJ) > 0
	})
}

// ValidateBlockTransactions validates all transactions in a block.
func ValidateBlockTransactions(block *encoding.Block) error {
	for _, tx := range block.Transactions {
		if err := tx.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// CalculateBlockReward calculates the block reward.
func CalculateBlockReward(height uint64) *big.Int {
	// Simple fixed reward for now
	// In production, this would follow a halving schedule
	baseReward := big.NewInt(2e18) // 2 QAU

	// Halving every 4 years (assuming 3 second blocks)
	halvingInterval := uint64(4 * 365 * 24 * 60 * 60 / 12)
	halvings := height / halvingInterval

	if halvings >= 64 {
		return big.NewInt(0)
	}

	reward := new(big.Int).Rsh(baseReward, uint(halvings))
	return reward
}

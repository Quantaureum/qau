// Quantaureum Node source, version 1.0.0.
// Package light implements a lightweight SPV node that syncs only block headers,
// verifies transactions via Merkle proofs, and stores neither full blocks nor state.
package light

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// BlockHeader holds the header fields a light node needs
type BlockHeader struct {
	Height     uint64
	ParentHash types.Hash
	StateRoot  types.Hash
	TxRoot     types.Hash
	Timestamp  int64
	Proposer   types.Address
	Signature  []byte
}

// LightNode implements a lightweight node that syncs only block headers
// It stores no full blocks or state and verifies transactions via Merkle proofs
type LightNode struct {
	mu sync.RWMutex

	// header storage
	headers map[uint64]*BlockHeader
	// latest height
	latestHeight uint64
	// trusted checkpoints (confirmed headers)
	checkpoints map[uint64]*BlockHeader
	// RPC client connecting to a full node
	rpcClient RPCClient
	// trusted validator public keys (for header signature verification)
	trustedPubKey *crypto.PublicKey
}

// NewLightNode creates a light node instance
func NewLightNode(rpcURL string) *LightNode {
	return &LightNode{
		headers:     make(map[uint64]*BlockHeader),
		checkpoints: make(map[uint64]*BlockHeader),
		rpcClient:   NewRPCClient(rpcURL),
	}
}

// SetTrustedPublicKey sets the trusted validator keys used to verify header signatures
func (ln *LightNode) SetTrustedPublicKey(pubKey *crypto.PublicKey) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	ln.trustedPubKey = pubKey
}

// SyncHeaders syncs headers, starting from the latest checkpoint or height 0
func (ln *LightNode) SyncHeaders() error {
	ln.mu.Lock()
	if ln.headers == nil {
		ln.headers = make(map[uint64]*BlockHeader)
	}
	ln.mu.Unlock()

	// fetch the remote tip height
	remoteHeight, err := ln.rpcClient.GetLatestHeight()
	if err != nil {
		return fmt.Errorf("failed to fetch remote height: %w", err)
	}

	// determine the starting height
	startHeight := uint64(0)
	ln.mu.RLock()
	if ln.latestHeight > 0 {
		startHeight = ln.latestHeight + 1
	}
	ln.mu.RUnlock()

	// sync headers one by one from the starting height
	for height := startHeight; height <= remoteHeight; height++ {
		header, err := ln.rpcClient.GetBlockHeader(height)
		if err != nil {
			return fmt.Errorf("failed to sync header at height %d: %w", height, err)
		}

		// verify the header
		if !ln.VerifyBlockHeader(header) {
			return fmt.Errorf("header verification failed at height %d", height)
		}

		ln.mu.Lock()
		ln.headers[height] = header
		ln.latestHeight = height
		ln.mu.Unlock()
	}

	return nil
}

// VerifyTransaction verifies that a transaction is contained in the given block
func (ln *LightNode) VerifyTransaction(txHash types.Hash, proof MerkleProof, blockHeight uint64) bool {
	ln.mu.RLock()
	header, exists := ln.headers[blockHeight]
	ln.mu.RUnlock()

	if !exists {
		return false
	}

	// verify the Merkle proof
	return VerifyMerkleProof(txHash, header.TxRoot, proof)
}

// GetBalance queries the balance via RPC (light nodes hold no state)
func (ln *LightNode) GetBalance(addr types.Address) (*big.Int, error) {
	return ln.rpcClient.GetBalance(addr)
}

// VerifyBlockHeader verifies the header signature
func (ln *LightNode) VerifyBlockHeader(header *BlockHeader) bool {
	if header == nil {
		return false
	}

	ln.mu.RLock()
	pubKey := ln.trustedPubKey
	ln.mu.RUnlock()

	// AUDIT (2026) HIGH-09 (BRDG-04): Fail-closed when no trusted public
	// key is configured. Previously, this fell back to verifyHeaderBasic
	// (parent hash + timestamp continuity only), which accepts any
	// self-consistent fake header chain. A malicious RPC or MITM could feed
	// arbitrary StateRoot/TxRoot headers and they'd be stored as canonical.
	//
	// Exception: height 0 (genesis/anchor header) has no signature to verify
	// and is trusted via out-of-band checkpoint.
	if pubKey == nil {
		if header.Height == 0 {
			return ln.verifyHeaderBasic(header)
		}
		return false
	}

	// compute the header's signature message
	msg := ln.headerSignMessage(header)
	if !crypto.Verify(pubKey, msg, header.Signature) {
		return false
	}

	return ln.verifyHeaderBasic(header)
}

// verifyHeaderBasic checks basic header validity
func (ln *LightNode) verifyHeaderBasic(header *BlockHeader) bool {
	if header == nil {
		return false
	}

	// check height and parent-hash continuity
	ln.mu.RLock()
	prevHeader, hasPrev := ln.headers[header.Height-1]
	ln.mu.RUnlock()

	if hasPrev {
		// the parent hash must match the previous header's hash
		prevHash := computeBlockHeaderHash(prevHeader)
		if header.ParentHash != prevHash {
			return false
		}
		// timestamps must increase
		if header.Timestamp < prevHeader.Timestamp {
			return false
		}
	}

	return true
}

// headerSignMessage computes the header's signature message
func (ln *LightNode) headerSignMessage(header *BlockHeader) []byte {
	// serialize the key fields into the signature message
	data := make([]byte, 8+32+32+32+8+20)
	offset := 0

	// Height
	putUint64(data[offset:], header.Height)
	offset += 8

	// ParentHash
	copy(data[offset:], header.ParentHash[:])
	offset += 32

	// StateRoot
	copy(data[offset:], header.StateRoot[:])
	offset += 32

	// TxRoot
	copy(data[offset:], header.TxRoot[:])
	offset += 32

	// Timestamp
	putUint64(data[offset:], uint64(header.Timestamp))
	offset += 8

	// Proposer
	copy(data[offset:], header.Proposer[:])

	return data
}

// AddCheckpoint adds a trusted checkpoint
func (ln *LightNode) AddCheckpoint(height uint64, header *BlockHeader) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	ln.checkpoints[height] = header
	ln.headers[height] = header
}

// GetLatestHeight returns the latest synced height
func (ln *LightNode) GetLatestHeight() uint64 {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	return ln.latestHeight
}

// GetHeader fetches the header at the given height
func (ln *LightNode) GetHeader(height uint64) (*BlockHeader, bool) {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	h, ok := ln.headers[height]
	return h, ok
}

// GetCheckpoint fetches the checkpoint at the given height
func (ln *LightNode) GetCheckpoint(height uint64) (*BlockHeader, bool) {
	ln.mu.RLock()
	defer ln.mu.RUnlock()
	h, ok := ln.checkpoints[height]
	return h, ok
}

// FromEncodingHeader converts an encoding.BlockHeader into the light node's BlockHeader
func FromEncodingHeader(h *encoding.BlockHeader) *BlockHeader {
	if h == nil {
		return nil
	}
	return &BlockHeader{
		Height:     h.Height,
		ParentHash: h.ParentHash,
		StateRoot:  h.StateRoot,
		TxRoot:     h.TxRoot,
		Timestamp:  h.Timestamp,
		Proposer:   h.ProposerAddr,
		Signature:  h.Signature,
	}
}

// ToEncodingHeader converts into an encoding.BlockHeader
func (h *BlockHeader) ToEncodingHeader() *encoding.BlockHeader {
	if h == nil {
		return nil
	}
	sig := h.Signature
	if sig == nil {
		sig = []byte{}
	}
	return &encoding.BlockHeader{
		Height:       h.Height,
		ParentHash:   h.ParentHash,
		StateRoot:    h.StateRoot,
		TxRoot:       h.TxRoot,
		Timestamp:    h.Timestamp,
		ProposerAddr: h.Proposer,
		Signature:    sig,
	}
}

// computeBlockHeaderHash computes the header hash
func computeBlockHeaderHash(header *BlockHeader) types.Hash {
	data := make([]byte, 8+32+32+32+8+20)
	offset := 0
	putUint64(data[offset:], header.Height)
	offset += 8
	copy(data[offset:], header.ParentHash[:])
	offset += 32
	copy(data[offset:], header.StateRoot[:])
	offset += 32
	copy(data[offset:], header.TxRoot[:])
	offset += 32
	putUint64(data[offset:], uint64(header.Timestamp))
	offset += 8
	copy(data[offset:], header.Proposer[:])
	return types.Keccak256Hash(data)
}

// putUint64 writes a uint64 big-endian
func putUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

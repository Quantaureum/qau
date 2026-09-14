// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"sync"
	"time"
)

// AUDIT (2026) HIGH-16: bounds and TTL for CompactBlockManager.pending
// to prevent unbounded memory growth from malicious peers.
const (
	maxPendingCompactBlocks = 1000            // cap on pending entries
	compactBlockTTL         = 5 * time.Minute // entries older than this are evicted
)

// CompactBlock implements compact block propagation (inspired by Ethereum's
// BlockBodies/BlockHeaders split and Bitcoin's compact blocks).
//
// PROBLEM: A full block with 1428 Dilithium3 txs is ~7.3MB. Broadcasting to 5
// peers = 36.5MB per block. During high TPS, this saturates bandwidth.
//
// SOLUTION: Instead of broadcasting the full block, broadcast only:
//   - Block header (~500 bytes)
//   - Transaction hashes (32 bytes × 1428 = 44KB)
//   Total: ~45KB vs 7.3MB = 99.4% reduction
//
// Receiver reconstructs the block from its local txpool. If any txs are missing,
// it requests them via TxHashRequest (already implemented in compact_tx.go).
//
// FLOW:
// 1. Producer broadcasts CompactBlock (header + tx hashes)
// 2. Receiver checks local txpool for each hash
// 3. Missing txs → TxHashRequest to producer
// 4. Producer responds with full txs
// 5. Receiver reconstructs full block and processes it

// CompactBlockMsg is a compact block announcement containing only the header
// and transaction hashes.
type CompactBlockMsg struct {
	Header    []byte   // Serialized block header
	TxHashes  [][]byte // 32-byte tx hashes
	BlockHash []byte   // 32-byte block hash (for dedup)
}

// EncodeCompactBlock encodes a compact block message.
func EncodeCompactBlock(cb *CompactBlockMsg) []byte {
	// Format: [4-byte headerLen][header][4-byte hashCount][hashes]
	totalLen := 4 + len(cb.Header) + 4 + len(cb.TxHashes)*32 + 32
	buf := make([]byte, totalLen)
	offset := 0

	// Header length + data
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(cb.Header)))
	offset += 4
	copy(buf[offset:], cb.Header)
	offset += len(cb.Header)

	// Tx hash count + hashes
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(cb.TxHashes)))
	offset += 4
	for _, h := range cb.TxHashes {
		copy(buf[offset:], h)
		offset += 32
	}

	// Block hash
	copy(buf[offset:], cb.BlockHash)

	return buf
}

// DecodeCompactBlock decodes a compact block message.
func DecodeCompactBlock(data []byte) (*CompactBlockMsg, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessageFormat
	}
	offset := 0

	// Header
	headerLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	// SECURITY (audit DATA-07): Cap header length and use uint64 bounds check
	// to prevent 32-bit int overflow when headerLen is large. Matches the
	// pattern in encoding/block.go (L18-013/L19-005 FIX).
	if headerLen > 10*1024*1024 {
		return nil, ErrInvalidMessageFormat
	}
	if uint64(offset)+uint64(headerLen) > uint64(len(data)) {
		return nil, ErrInvalidMessageFormat
	}
	header := make([]byte, headerLen)
	copy(header, data[offset:offset+int(headerLen)])
	offset += int(headerLen)

	// Tx hashes
	if offset+4 > len(data) {
		return nil, ErrInvalidMessageFormat
	}
	hashCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if hashCount > 10000 {
		return nil, ErrInvalidMessageFormat
	}
	if offset+int(hashCount)*32+32 > len(data) {
		return nil, ErrInvalidMessageFormat
	}
	hashes := make([][]byte, hashCount)
	for i := uint32(0); i < hashCount; i++ {
		h := make([]byte, 32)
		copy(h, data[offset:offset+32])
		offset += 32
		hashes[i] = h
	}

	// Block hash
	blockHash := make([]byte, 32)
	copy(blockHash, data[offset:offset+32])

	return &CompactBlockMsg{
		Header:    header,
		TxHashes:  hashes,
		BlockHash: blockHash,
	}, nil
}

// CompactBlockManager manages compact block propagation.
type CompactBlockManager struct {
	host *Host

	// pendingCompactBlocks stores compact blocks waiting for missing txs.
	// Key: block hash hex, Value: CompactBlockMsg
	mu      sync.RWMutex
	pending map[string]*CompactBlockMsg
	// AUDIT (2026) HIGH-16: track insertion time for TTL eviction.
	pendingTimes map[string]time.Time

	// txLookup is a reference to CompactTxManager's lookup (shared)
	compactTx *CompactTxManager
}

// NewCompactBlockManager creates a new compact block manager.
func NewCompactBlockManager(host *Host, ctx *CompactTxManager) *CompactBlockManager {
	return &CompactBlockManager{
		host:         host,
		pending:      make(map[string]*CompactBlockMsg),
		pendingTimes: make(map[string]time.Time),
		compactTx:    ctx,
	}
}

// BroadcastCompactBlock broadcasts a compact block (header + tx hashes).
// The receiver reconstructs the full block from its local txpool.
func (m *CompactBlockManager) BroadcastCompactBlock(header []byte, txHashes [][]byte, blockHash []byte) {
	if m == nil {
		return
	}

	cb := &CompactBlockMsg{
		Header:    header,
		TxHashes:  txHashes,
		BlockHash: blockHash,
	}
	data := EncodeCompactBlock(cb)
	msgData, err := EncodeMessage(MsgTypeCompactBlock, data)
	if err != nil {
		return
	}
	m.host.BroadcastRaw(m.host.ctx, msgData) //nolint:errcheck
}

// HandleCompactBlock processes a received compact block.
// Returns:
// - missingHashes: tx hashes not found in local lookup (need to request)
// - blockHash: the block's hash
//
// R33 P2P-09 FIX (2026-07-28): Validate that cb.BlockHash matches
// HashData(cb.Header). Previously the blockHash field was attacker-controlled
// and unchecked. A malicious peer could send CompactBlocks with random
// blockHash values, each landing as a distinct entry in the pending map
// (bounded by maxPendingCompactBlocks=1000, but still 1000 junk entries
// evicting legitimate pending blocks). It could also send a CompactBlock
// with blockHash=X but header=H where X != Hash(H), causing later
// reconstruction to fail when the full block with hash(X) is looked up.
// Fix: recompute the header hash locally and require it to match the
// announced blockHash. Mismatches are silently dropped (the peer is
// already authenticated at the connection level; this is integrity
// validation, not authentication).
func (m *CompactBlockManager) HandleCompactBlock(cb *CompactBlockMsg) (missingHashes [][]byte, blockHash []byte) {
	if m == nil {
		return nil, nil
	}

	// R33 P2P-09: Integrity check — blockHash must match HashData(header).
	if len(cb.BlockHash) != 32 || len(cb.Header) == 0 {
		return nil, nil
	}
	computedHash := HashData(cb.Header)
	if !bytesEqual(cb.BlockHash, computedHash) {
		// Block hash mismatch — silently drop. Don't log at warn level
		// because an honest peer may be propagating a stale or reorg'd
		// block; this is not necessarily malicious.
		return nil, nil
	}

	var missing [][]byte
	for _, h := range cb.TxHashes {
		if m.compactTx == nil || !m.compactTx.HasTx(h) {
			missing = append(missing, h)
		}
	}

	// Store as pending if we have missing txs.
	// AUDIT (2026) HIGH-16: enforce max entries + TTL to prevent
	// unbounded memory growth from malicious peers flooding unique
	// block hashes with missing tx hashes.
	if len(missing) > 0 {
		key := string(cb.BlockHash)
		m.mu.Lock()
		m.evictExpiredLocked()
		// If at capacity, drop the oldest entry to make room.
		if len(m.pending) >= maxPendingCompactBlocks {
			if _, exists := m.pending[key]; !exists {
				m.evictOldestLocked()
			}
		}
		m.pending[key] = cb
		m.pendingTimes[key] = time.Now()
		m.mu.Unlock()
	}

	return missing, cb.BlockHash
}

// bytesEqual is a constant-time byte slice comparison.
// Used for hash integrity checks where timing side-channels could leak
// information about how many bytes matched.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// evictExpiredLocked removes entries older than compactBlockTTL. Caller must
// hold m.mu.
func (m *CompactBlockManager) evictExpiredLocked() {
	now := time.Now()
	for k, t := range m.pendingTimes {
		if now.Sub(t) > compactBlockTTL {
			delete(m.pending, k)
			delete(m.pendingTimes, k)
		}
	}
}

// evictOldestLocked removes the single oldest entry. Caller must hold m.mu.
func (m *CompactBlockManager) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, t := range m.pendingTimes {
		if first || t.Before(oldestTime) {
			oldestKey = k
			oldestTime = t
			first = false
		}
	}
	if oldestKey != "" {
		delete(m.pending, oldestKey)
		delete(m.pendingTimes, oldestKey)
	}
}

// IsBlockPending checks if a compact block is waiting for missing txs.
func (m *CompactBlockManager) IsBlockPending(blockHash []byte) bool {
	if m == nil {
		return false
	}
	key := string(blockHash)
	m.mu.RLock()
	_, ok := m.pending[key]
	m.mu.RUnlock()
	return ok
}

// RemovePendingBlock removes a pending compact block.
func (m *CompactBlockManager) RemovePendingBlock(blockHash []byte) {
	if m == nil {
		return
	}
	key := string(blockHash)
	m.mu.Lock()
	delete(m.pending, key)
	delete(m.pendingTimes, key)
	m.mu.Unlock()
}

// GetPendingBlock retrieves a pending compact block.
func (m *CompactBlockManager) GetPendingBlock(blockHash []byte) *CompactBlockMsg {
	if m == nil {
		return nil
	}
	key := string(blockHash)
	m.mu.RLock()
	cb := m.pending[key]
	m.mu.RUnlock()
	return cb
}

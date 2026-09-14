// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"encoding/binary"
	"sync"
	"time"
)

// CompactTxManager implements compact transaction propagation.
//
// PROBLEM: Each Dilithium3 transaction is ~5.5KB. Broadcasting 4096 txs to 5 peers
// = 4096 × 5.5KB × 5 = 112MB. This saturates network bandwidth and causes txCh
// overflow, resulting in dropped transactions and low block utilization (47.8%).
//
// SOLUTION (inspired by Ethereum eth/68): Instead of broadcasting full transactions,
// only broadcast 32-byte tx hashes. Peers that don't have a tx for a given hash
// request the full transaction. This reduces bandwidth by ~99%:
//   - Old: 4096 × 5.5KB × 5 peers = 112MB
//   - New: 4096 × 32B × 5 peers = 640KB (hash announce)
//         + only missing txs requested (typically <10% = ~5.6MB)
//         = ~6.2MB total (95% reduction)
//
// FLOW:
// 1. Node A broadcasts tx hash announce to all peers
// 2. Node B receives the hash, checks its local txpool — if missing, sends a TxHashRequest
// 3. Node A responds with full tx data
// 4. Node B adds to txpool and re-broadcasts hash to its peers

// TxHashAnnounce is a batch of transaction hashes announced to peers.
type TxHashAnnounce struct {
	Hashes [][]byte // 32-byte hashes
}

// TxHashRequest requests full transaction data for given hashes.
type TxHashRequest struct {
	Hashes [][]byte // 32-byte hashes
}

// TxHashResponse returns full transaction data for requested hashes.
type TxHashResponse struct {
	Txs [][]byte // Full transaction data
}

// EncodeTxHashAnnounce encodes a tx hash announce message.
//
// R33 P2-15 FIX (2026-07-28): Added hash length validation. Previously
// this function assumed every hash in a.Hashes was exactly 32 bytes (the
// on-wire format is [4-byte count][32-byte hash]*). The `copy(dst, h)`
// call silently copied only min(32, len(h)) bytes when h was shorter
// (leaving zero-padded garbage on the wire) OR — more dangerously —
// copied MORE than 32 bytes when len(h) > 32, corrupting the next hash
// slot in the buffer. A malicious or buggy caller passing a 64-byte
// hash for a non-final entry would silently shift every subsequent
// hash, causing the receiver to look up the wrong transactions. The fix
// rejects any hash whose length is not exactly 32 bytes.
func EncodeTxHashAnnounce(a *TxHashAnnounce) ([]byte, error) {
	for _, h := range a.Hashes {
		if len(h) != 32 {
			return nil, ErrInvalidMessageFormat
		}
	}
	buf := make([]byte, 4+len(a.Hashes)*32)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(a.Hashes)))
	for i, h := range a.Hashes {
		copy(buf[4+i*32:], h)
	}
	return buf, nil
}

// DecodeTxHashAnnounce decodes a tx hash announce message.
func DecodeTxHashAnnounce(data []byte) (*TxHashAnnounce, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessageFormat
	}
	count := binary.BigEndian.Uint32(data[:4])
	if count > 10000 {
		return nil, ErrInvalidMessageFormat
	}
	if len(data) < int(4+count*32) {
		return nil, ErrInvalidMessageFormat
	}
	hashes := make([][]byte, count)
	for i := uint32(0); i < count; i++ {
		h := make([]byte, 32)
		copy(h, data[4+i*32:4+(i+1)*32])
		hashes[i] = h
	}
	return &TxHashAnnounce{Hashes: hashes}, nil
}

// EncodeTxHashRequest encodes a tx hash request message.
//
// R33 P2-15 FIX (2026-07-28): Added hash length validation, same as
// EncodeTxHashAnnounce. Without this check, a hash with len != 32 would
// either be silently zero-padded (if shorter) or overflow into the next
// hash slot (if longer), corrupting the wire format and causing the
// receiver to fetch the wrong transactions. See EncodeTxHashAnnounce for
// the full rationale.
func EncodeTxHashRequest(r *TxHashRequest) ([]byte, error) {
	for _, h := range r.Hashes {
		if len(h) != 32 {
			return nil, ErrInvalidMessageFormat
		}
	}
	buf := make([]byte, 4+len(r.Hashes)*32)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(r.Hashes)))
	for i, h := range r.Hashes {
		copy(buf[4+i*32:], h)
	}
	return buf, nil
}

// DecodeTxHashRequest decodes a tx hash request message.
func DecodeTxHashRequest(data []byte) (*TxHashRequest, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessageFormat
	}
	count := binary.BigEndian.Uint32(data[:4])
	if count > 1000 {
		return nil, ErrInvalidMessageFormat
	}
	if len(data) < int(4+count*32) {
		return nil, ErrInvalidMessageFormat
	}
	hashes := make([][]byte, count)
	for i := uint32(0); i < count; i++ {
		h := make([]byte, 32)
		copy(h, data[4+i*32:4+(i+1)*32])
		hashes[i] = h
	}
	return &TxHashRequest{Hashes: hashes}, nil
}

// EncodeTxHashResponse encodes a tx hash response message.
func EncodeTxHashResponse(r *TxHashResponse) []byte {
	// Format: [4-byte count][for each tx: 4-byte length + tx data]
	totalLen := 4
	for _, tx := range r.Txs {
		totalLen += 4 + len(tx)
	}
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(r.Txs)))
	offset := 4
	for _, tx := range r.Txs {
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(tx)))
		offset += 4
		copy(buf[offset:], tx)
		offset += len(tx)
	}
	return buf
}

// DecodeTxHashResponse decodes a tx hash response message.
func DecodeTxHashResponse(data []byte) (*TxHashResponse, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessageFormat
	}
	count := binary.BigEndian.Uint32(data[:4])
	if count > 1000 {
		return nil, ErrInvalidMessageFormat
	}
	txs := make([][]byte, 0, count)
	offset := 4
	for i := uint32(0); i < count; i++ {
		if offset+4 > len(data) {
			return nil, ErrInvalidMessageFormat
		}
		txLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if txLen > 1024*1024 || offset+int(txLen) > len(data) {
			return nil, ErrInvalidMessageFormat
		}
		tx := make([]byte, txLen)
		copy(tx, data[offset:offset+int(txLen)])
		offset += int(txLen)
		txs = append(txs, tx)
	}
	return &TxHashResponse{Txs: txs}, nil
}

// CompactTxManager manages compact transaction propagation.
type CompactTxManager struct {
	host *Host

	// txLookup maps tx hash → tx data, for responding to hash requests.
	// Populated when a tx is added to the local txpool.
	mu        sync.RWMutex
	txLookup  map[string][]byte // hash hex → tx data
	maxLookup int

	// pendingHashes tracks hashes we've announced but haven't yet received
	// full tx data for. Used to detect which hashes need to be requested.
	// AUDIT (2026) P2P-06: Added maxPendingMissing bound. Without it,
	// an attacker can flood with TxHashAnnounce messages containing up to
	// 10000 unknown hashes each, and pendingMissing grows unboundedly
	// (cleanup only runs every 30s). Cap at 100000 entries (~3.2MB for
	// 32-byte keys) and reject new entries beyond the cap.
	pendingMu         sync.Mutex
	pendingMissing    map[string]time.Time // hash hex → announce time
	maxPendingMissing int
	requestTimeout    time.Duration

	ctx context.Context
}

// NewCompactTxManager creates a new compact tx manager.
func NewCompactTxManager(host *Host) *CompactTxManager {
	return &CompactTxManager{
		host:              host,
		txLookup:          make(map[string][]byte),
		maxLookup:         50000, // Match SignatureCache size
		pendingMissing:    make(map[string]time.Time),
		maxPendingMissing: 100000, // AUDIT (2026) P2P-06: bound memory
		requestTimeout:    5 * time.Second,
		ctx:               host.ctx,
	}
}

// StoreTx stores a transaction in the lookup table for responding to hash requests.
// Called when a tx is added to the local txpool.
func (m *CompactTxManager) StoreTx(txHash []byte, txData []byte) {
	if m == nil {
		return
	}
	key := string(txHash)
	m.mu.Lock()
	// Evict oldest entries if at capacity (simple LRU-ish: just delete random)
	if len(m.txLookup) >= m.maxLookup {
		for k := range m.txLookup {
			delete(m.txLookup, k)
			break
		}
	}
	// Store a copy to avoid aliasing issues
	dataCopy := make([]byte, len(txData))
	copy(dataCopy, txData)
	m.txLookup[key] = dataCopy
	m.mu.Unlock()
}

// GetTx retrieves a transaction by hash. Returns nil if not found.
func (m *CompactTxManager) GetTx(txHash []byte) []byte {
	if m == nil {
		return nil
	}
	key := string(txHash)
	m.mu.RLock()
	data := m.txLookup[key]
	m.mu.RUnlock()
	return data
}

// HasTx checks if a transaction is in the lookup table.
func (m *CompactTxManager) HasTx(txHash []byte) bool {
	if m == nil {
		return false
	}
	key := string(txHash)
	m.mu.RLock()
	_, ok := m.txLookup[key]
	m.mu.RUnlock()
	return ok
}

// BroadcastTxHashes broadcasts a batch of tx hashes to all peers.
// This is the compact alternative to broadcasting full tx data.
func (m *CompactTxManager) BroadcastTxHashes(hashes [][]byte) {
	if m == nil || len(hashes) == 0 {
		return
	}

	// Batch hashes into groups of 256 to stay within message size limits
	const maxHashesPerMsg = 256
	for i := 0; i < len(hashes); i += maxHashesPerMsg {
		end := i + maxHashesPerMsg
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := hashes[i:end]

		announce := &TxHashAnnounce{Hashes: batch}
		data, err := EncodeTxHashAnnounce(announce)
		if err != nil {
			// R33 P2-15: hash length validation failed — skip this batch.
			continue
		}
		msgData, err := EncodeMessage(MsgTypeTxHashAnnounce, data)
		if err != nil {
			continue
		}
		// Broadcast to all peers
		m.host.BroadcastRaw(m.ctx, msgData)
	}
}

// HandleTxHashAnnounce processes a received tx hash announce.
// Returns the list of hashes that need to be requested (not in local lookup).
func (m *CompactTxManager) HandleTxHashAnnounce(announce *TxHashAnnounce) [][]byte {
	if m == nil {
		return nil
	}

	var missing [][]byte
	for _, hash := range announce.Hashes {
		if !m.HasTx(hash) {
			// AUDIT (2026) P2P-06: Enforce maxPendingMissing bound.
			// If the pending map is full, skip tracking (the hash is
			// still added to `missing` for immediate request, but not
			// stored long-term). This prevents memory exhaustion from
			// hash flooding.
			key := string(hash)
			m.pendingMu.Lock()
			if len(m.pendingMissing) < m.maxPendingMissing {
				m.pendingMissing[key] = time.Now()
			}
			m.pendingMu.Unlock()
			missing = append(missing, hash)
		}
	}
	return missing
}

// RequestMissingTxs sends a TxHashRequest for the given hashes to a specific peer.
func (m *CompactTxManager) RequestMissingTxs(peerID PeerID, hashes [][]byte) {
	if m == nil || len(hashes) == 0 {
		return
	}

	// Batch requests into groups of 100
	const maxHashesPerRequest = 100
	for i := 0; i < len(hashes); i += maxHashesPerRequest {
		end := i + maxHashesPerRequest
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := hashes[i:end]

		req := &TxHashRequest{Hashes: batch}
		data, err := EncodeTxHashRequest(req)
		if err != nil {
			// R33 P2-15: hash length validation failed — skip this batch.
			continue
		}
		msgData, err := EncodeMessage(MsgTypeTxHashRequest, data)
		if err != nil {
			continue
		}
		m.host.SendRaw(peerID, msgData) //nolint:errcheck
	}
}

// HandleTxHashRequest processes a tx hash request from a peer.
// Returns the full tx data for all found hashes.
func (m *CompactTxManager) HandleTxHashRequest(req *TxHashRequest) *TxHashResponse {
	if m == nil {
		return nil
	}

	var txs [][]byte
	for _, hash := range req.Hashes {
		txData := m.GetTx(hash)
		if txData != nil {
			txs = append(txs, txData)
		}
	}
	if len(txs) == 0 {
		return nil
	}
	return &TxHashResponse{Txs: txs}
}

// HandleTxHashResponse processes a tx hash response containing full tx data.
// Returns the list of tx data that should be added to the txpool.
//
// R33 P2P-09 FIX (2026-07-28): Previously this accepted ANY txData from a peer,
// even txs we never requested. A malicious peer could:
//  1. Send unsolicited txs to pollute the compactTx lookup cache
//  2. Send txs whose hash doesn't match any pending request, bypassing
//     the per-hash dedup that legitimate TxHashRequest/Response enforces
//  3. Pre-populate the cache so that when a victim node later receives a
//     CompactBlock announcement, it believes it "already has" the tx and
//     skips requesting the real one — causing block reconstruction failure.
//
// Fix: only accept txData whose hash is in pendingMissing (i.e., we asked
// for it). Unsolicited txs are silently dropped. The hash is computed
// locally (not trusted from the wire) so a peer can't lie about identity.
//
// R33 P3-03 FIX (2026-07-28): RESIDUAL RISK DOCUMENTATION.
// The P2P-09 fix provides hash-based request-response correlation: a
// response is accepted ONLY IF its hash matches a pending missing entry.
// This blocks unsolicited tx injection but does NOT verify WHICH peer
// answers the request — any peer can fulfill any pending request.
//
// A more rigorous fix would add:
//  1. A RequestID nonce to TxHashRequest/TxHashResponse, echoed back by
//     the responder, so the requester can match responses to specific
//     requests.
//  2. Per-peer pending-request tracking: record (peerID, requestID, hashes)
//     and reject responses from peers that were not asked.
//
// We deliberately do NOT implement (1) and (2) because:
//   - The hash-based correlation already prevents cache pollution (the
//     primary risk identified in P2P-09). A peer cannot inject a tx we
//     did not request.
//   - Per-peer tracking would introduce complexity and failure modes
//     (e.g., if a peer disconnects after we sent a request, we would
//     need a fallback to accept responses from other peers — defeating
//     the purpose of per-peer binding).
//   - The txs themselves are individually verified by the txpool's
//     signature/gas/nonce checks before acceptance, so even a malicious
//     responder can only deliver validly-signed txs that we requested.
//   - This is a P3 LOW/INFO severity item; the residual risk (a peer
//     answering another peer's request) is equivalent to the peer simply
//     relaying the tx via normal gossip — no new attack surface.
//
// If a future audit upgrades this severity, the fix shape is:
//   - Add `RequestID uint64` to TxHashRequest and TxHashResponse.
//   - Track `pendingRequests map[peerID]map[uint64][]byte` in CompactTxManager.
//   - On response, verify (peerID, RequestID) matches an outstanding
//     request and that returned hashes are a subset of the requested set.
func (m *CompactTxManager) HandleTxHashResponse(resp *TxHashResponse) [][]byte {
	if m == nil {
		return nil
	}

	var accepted [][]byte
	for _, txData := range resp.Txs {
		hash := HashData(txData)
		key := string(hash)

		m.pendingMu.Lock()
		_, requested := m.pendingMissing[key]
		if requested {
			delete(m.pendingMissing, key)
		}
		m.pendingMu.Unlock()

		if !requested {
			// R33 P2P-09: Drop unsolicited tx. Don't store in lookup, don't
			// return to caller for txpool insertion.
			continue
		}

		// Store in lookup only if we actually requested it
		m.StoreTx(hash, txData)
		accepted = append(accepted, txData)
	}

	return accepted
}

// CleanupPending removes expired pending hash entries.
// Called periodically to prevent memory leaks from unresponded hash announces.
func (m *CompactTxManager) CleanupPending() {
	if m == nil {
		return
	}
	cutoff := time.Now().Add(-m.requestTimeout)
	m.pendingMu.Lock()
	for key, t := range m.pendingMissing {
		if t.Before(cutoff) {
			delete(m.pendingMissing, key)
		}
	}
	m.pendingMu.Unlock()
}

// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	// BlobStorageRetentionSlots is the legacy hard-coded blob retention
	// window. DA- (2026-07-16): production code should use
	// DefaultDASRetentionConfig().BlobRetentionSlots instead — that value
	// is validated against the session/attest windows. This constant is
	// kept aligned with the default (2048 slots) for any external caller
	// that still references it, but it is NOT validated and should not
	// be used for new code.
	BlobStorageRetentionSlots = 2048
	MaxBlobStorageSize        = 256 * 1024 * 1024
	BlobGCTickerInterval      = 60 * time.Second
	MsgTypeDASSampleReq       = uint8(50)
	MsgTypeDASSampleResp      = uint8(51)
)

type BlobStorageEntry struct {
	Slot        uint64
	BlobIndex   int
	Matrix      SparseBlobMatrix
	Commitments []KZGCommitment
	StoredAt    time.Time
}

type BlobStorage struct {
	entries     map[string]*BlobStorageEntry
	mu          sync.RWMutex
	maxSize     int64
	currentSize int64
	retention   DASRetentionConfig
}

func NewBlobStorage() *BlobStorage {
	return &BlobStorage{
		entries:   make(map[string]*BlobStorageEntry),
		maxSize:   MaxBlobStorageSize,
		retention: DefaultDASRetentionConfig(),
	}
}

func NewBlobStorageWithRetention(retention DASRetentionConfig) *BlobStorage {
	return &BlobStorage{
		entries:   make(map[string]*BlobStorageEntry),
		maxSize:   MaxBlobStorageSize,
		retention: retention,
	}
}

// SetRetentionConfig updates the retention configuration.
// DA- (2026-07-16): Rejects invalid configurations (those violating
// the Blob >= Session >= Attest > Decay invariants) and keeps the previous
// config — fail-closed against accidental availability regression.
func (s *BlobStorage) SetRetentionConfig(cfg DASRetentionConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validateAndLogRetention(cfg, "BlobStorage.SetRetentionConfig") {
		return
	}
	s.retention = cfg
}

func (s *BlobStorage) key(slot uint64, blobIndex int) string {
	return fmt.Sprintf("%d:%d", slot, blobIndex)
}

func (s *BlobStorage) entrySize(entry *BlobStorageEntry) int64 {
	size := int64(len(entry.Commitments) * 48)
	size += entry.Matrix.MemoryBytes()
	return size
}

func (s *BlobStorage) StoreMatrix(slot uint64, blobIndex int, matrix BlobMatrixExtended, commitments []KZGCommitment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// P1-13 (2026-07-14): Infer originalCount for sparse storage.
	// When commitments are provided (production path), len(commitments) = n
	// (original blob count). When nil (test path), default to MaxBlobColumns
	// and auto-compute commitments for all columns.
	originalCount := MaxBlobColumns
	if commitments != nil {
		originalCount = len(commitments)
		if originalCount > MaxBlobColumns {
			originalCount = MaxBlobColumns
		}
	} else {
		commitments = ComputeKZGCommitmentsForMatrix(matrix, MaxBlobColumnsExt)
	}

	k := s.key(slot, blobIndex)
	if _, exists := s.entries[k]; exists {
		return nil
	}

	entry := &BlobStorageEntry{
		Slot:        slot,
		BlobIndex:   blobIndex,
		Matrix:      NewSparseBlobMatrix(matrix, originalCount),
		Commitments: commitments,
		StoredAt:    time.Now(),
	}
	entrySize := s.entrySize(entry)

	if s.currentSize+entrySize > s.maxSize {
		s.evictOldest()
	}

	s.entries[k] = entry
	s.currentSize += entrySize

	return nil
}

func (s *BlobStorage) GetCell(slot uint64, blobIndex, row, col int) (*Cell, *KZGCommitment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k := s.key(slot, blobIndex)
	entry, exists := s.entries[k]
	if !exists {
		return nil, nil, fmt.Errorf("blob not found: slot=%d, index=%d", slot, blobIndex)
	}

	if col < 0 || col >= MaxBlobColumnsExt {
		return nil, nil, fmt.Errorf("column out of range: %d", col)
	}
	if row < 0 || row >= CellsPerBlobExtended {
		return nil, nil, fmt.Errorf("row out of range: %d", row)
	}

	cell := entry.Matrix.GetCellPtr(row, col)

	// R37-P3-17 FIX (2026-07-31): blobIndex must be non-negative.
	// A negative index would silently access the wrong memory (Go slices
	// do not bounds-check negative indices in the same way; they panic).
	var commitment *KZGCommitment
	if blobIndex >= 0 && blobIndex < len(entry.Commitments) {
		commitment = &entry.Commitments[blobIndex]
	}

	return cell, commitment, nil
}

func (s *BlobStorage) GetCommitments(slot uint64) []KZGCommitment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var commitments []KZGCommitment
	for _, entry := range s.entries {
		if entry.Slot == slot {
			commitments = entry.Commitments
			break
		}
	}
	return commitments
}

func (s *BlobStorage) HasBlob(slot uint64, blobIndex int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.entries[s.key(slot, blobIndex)]
	return exists
}

func (s *BlobStorage) GetBlobCount(slot uint64) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, entry := range s.entries {
		if entry.Slot == slot {
			count++
		}
	}
	return count
}

func (s *BlobStorage) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	var oldestEntry *BlobStorageEntry

	for k, entry := range s.entries {
		if oldestKey == "" || entry.StoredAt.Before(oldestTime) ||
			(entry.StoredAt.Equal(oldestTime) && k < oldestKey) {
			// DA-FIX (2026-07-17): Use the entry key as a tie-breaker
			// when StoredAt is identical. Go's map iteration order is
			// non-deterministic, so without a deterministic tie-breaker
			// different nodes could evict different blobs for the same
			// timestamp, causing storage state divergence and inconsistent
			// DAS sampling across the committee.
			oldestKey = k
			oldestTime = entry.StoredAt
			oldestEntry = entry
		}
	}

	if oldestKey != "" {
		delete(s.entries, oldestKey)
		if oldestEntry != nil {
			s.currentSize -= s.entrySize(oldestEntry)
		}
	}
}

func (s *BlobStorage) GC(currentSlot uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	retentionSlots := s.retention.BlobRetentionSlots
	for k, entry := range s.entries {
		if entry.Slot+retentionSlots < currentSlot {
			s.currentSize -= s.entrySize(entry)
			delete(s.entries, k)
		}
	}
}

func (s *BlobStorage) Stats() (entryCount int, totalSize int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries), s.currentSize
}

type BlobNetworkManager struct {
	storage    *BlobStorage
	dasClient  *DASClient
	mu         sync.RWMutex
	peerGetter func(peerID string, msgType uint8, data []byte) ([]byte, error)
	peerList   func() []string
}

func NewBlobNetworkManager(storage *BlobStorage, dasClient *DASClient) *BlobNetworkManager {
	return &BlobNetworkManager{
		storage:   storage,
		dasClient: dasClient,
	}
}

func (m *BlobNetworkManager) SetPeerGetter(getter func(peerID string, msgType uint8, data []byte) ([]byte, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerGetter = getter
}

func (m *BlobNetworkManager) SetPeerList(lister func() []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerList = lister
}

func (m *BlobNetworkManager) RequestCell(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
	m.mu.RLock()
	peerGetter := m.peerGetter
	peerList := m.peerList
	m.mu.RUnlock()

	if peerGetter == nil || peerList == nil {
		return nil, fmt.Errorf("network not configured")
	}

	peers := peerList()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers available")
	}

	// R38-P1-06 FIX (2026-08-01, RequestID nonce): mint a unique 8-byte
	// nonce for this request so we can bind the peer's response back to
	// THIS call via resp.RequestID == nonce. Without a per-call nonce a
	// peer (or a tampering peerGetter shim) could substitute one precomputed
	// response for another, fooling the caller into accepting cells it
	// never actually sampled. ServeCellRequest already echoes req.RequestID
	// verbatim, so honest peers return the matching non-zero nonce; a
	// mismatch here is a hard reject.
	nonce, err := m.mintRequestIDNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to mint RequestID nonce: %w", err)
	}

	req := DASSampleRequest{
		RequestID: nonce,
		Slot:      slot,
		BlobIndex: blobIndex,
		CellRow:   row,
		CellCol:   col,
	}

	reqData := encodeDASSampleRequest(req)

	peerIdx, err := m.randomPeerIndex(len(peers))
	if err != nil {
		return nil, fmt.Errorf("failed to select peer for sampling: %w", err)
	}
	peer := peers[peerIdx]

	respData, err := peerGetter(peer, MsgTypeDASSampleReq, reqData)
	if err != nil {
		return nil, fmt.Errorf("peer request failed: %w", err)
	}

	resp, err := decodeDASSampleResponse(respData)
	if err != nil {
		return nil, err
	}

	// R38-P1-06 FIX (2026-08-01, response binding): After decoding, verify
	// the response's coordinates AND RequestID match what we asked for.
	// Without this check a malicious peer (or a buggy/compromised
	// peerGetter) can return a valid cell for a totally different address,
	// fooling the caller into believing a specific cell is available. The
	// coordinate check mirrors the caller-side check already present in
	// DASClient.Sample; the RequestID check additionally rejects precomputed
	// or cross-call response substitution.
	if resp.Slot != req.Slot ||
		resp.BlobIndex != req.BlobIndex ||
		resp.CellRow != req.CellRow ||
		resp.CellCol != req.CellCol {
		return nil, fmt.Errorf("response coordinate mismatch: got (slot=%d, blob=%d, row=%d, col=%d), want (slot=%d, blob=%d, row=%d, col=%d) (R38-P1-06)",
			resp.Slot, resp.BlobIndex, resp.CellRow, resp.CellCol,
			req.Slot, req.BlobIndex, req.CellRow, req.CellCol)
	}
	if resp.RequestID != req.RequestID {
		return nil, fmt.Errorf("response RequestID mismatch: got %d, want %d (R38-P1-06)", resp.RequestID, req.RequestID)
	}

	return resp, nil
}

// mintRequestIDNonce generates a per-call 8-byte nonce bound to the request
// frame so RequestCell can reject responses that do not echo it. R38-P1-06.
// On crypto/rand failure we refuse to sample rather than risk a degenerate
// (zero or repeating) nonce — a degenerate nonce would let an attacker
// precompute one valid response and answer every request with it.
func (m *BlobNetworkManager) mintRequestIDNonce() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	nonce := binary.BigEndian.Uint64(b)
	// Refuse the (astronomically unlikely) zero nonce: a zero RequestID is
	// what the wire would carry if the field were never populated (the pre-
	// R38-P1-06 state), so treating it as valid would silently re-open the
	// exact window this fix closes.
	if nonce == 0 {
		return 0, fmt.Errorf("minted zero nonce — refusing to issue a degenerate RequestID")
	}
	return nonce, nil
}

func (m *BlobNetworkManager) ServeCellRequest(data []byte) ([]byte, error) {
	req, err := decodeDASSampleRequest(data)
	if err != nil {
		return nil, err
	}

	cell, commitment, err := m.storage.GetCell(req.Slot, req.BlobIndex, req.CellRow, req.CellCol)
	if err != nil {
		return nil, err
	}

	if commitment == nil {
		return nil, fmt.Errorf("no commitment available for slot=%d blobIndex=%d", req.Slot, req.BlobIndex)
	}

	proof, ok := ComputeCellProof(*cell, req.CellRow, req.CellCol, *commitment)
	if !ok {
		return nil, fmt.Errorf("cell proof computation failed")
	}

	resp := DASSampleResponse{
		// P1-12 (RPC-H1, 2026-07-19): Echo the RequestID so the requester
		// can route the response through its dasPending map. Without this,
		// concurrent sampling goroutines reading a shared channel would
		// observe each other's responses, allowing a malicious peer to
		// inject arbitrary cell data matched to the wrong request.
		RequestID: req.RequestID,
		Slot:      req.Slot,
		BlobIndex: req.BlobIndex,
		CellRow:   req.CellRow,
		CellCol:   req.CellCol,
		Cell:      *cell,
		Proof:     proof,
	}

	_ = commitment

	return encodeDASSampleResponse(resp), nil
}

func (m *BlobNetworkManager) randomPeerIndex(count int) (int, error) {
	if count <= 0 {
		return 0, fmt.Errorf("randomPeerIndex: count must be > 0")
	}
	b := make([]byte, 8)
	// DA-FIX (2026-07-17): Previously, on RNG failure this function
	// returned 0 — always selecting peer[0]. An attacker who can exhaust
	// system entropy (or otherwise cause crypto/rand to fail) could force
	// the node to always request blob data from peer[0], enabling eclipse
	// attacks or data withholding against a fixed peer. Return an error
	// instead so the caller can refuse to sample rather than bias selection.
	if _, err := rand.Read(b); err != nil {
		return 0, fmt.Errorf("randomPeerIndex: crypto/rand.Read failed: %w", err)
	}
	return int(binary.BigEndian.Uint64(b) % uint64(count)), nil
}

// P1-12 (RPC-H1, 2026-07-19): Wire format now carries RequestID (8 bytes) at
// the head so the requester can correlate responses via a pending-requests
// map. Layout:
//
//	[0:8)   RequestID  (uint64, big-endian)
//	[8:16)  Slot       (uint64, big-endian)
//	[16:20) BlobIndex  (uint32)
//	[20:24) CellRow    (uint32)
//	[24:28) CellCol    (uint32)
func encodeDASSampleRequest(req DASSampleRequest) []byte {
	buf := make([]byte, DASSampleRequestSize)
	binary.BigEndian.PutUint64(buf[0:8], req.RequestID)
	binary.BigEndian.PutUint64(buf[8:16], req.Slot)
	binary.BigEndian.PutUint32(buf[16:20], uint32(req.BlobIndex))
	binary.BigEndian.PutUint32(buf[20:24], uint32(req.CellRow))
	binary.BigEndian.PutUint32(buf[24:28], uint32(req.CellCol))
	return buf
}

func decodeDASSampleRequest(data []byte) (DASSampleRequest, error) {
	if len(data) < DASSampleRequestSize {
		return DASSampleRequest{}, fmt.Errorf("data too short: got %d, want %d", len(data), DASSampleRequestSize)
	}
	return DASSampleRequest{
		RequestID: binary.BigEndian.Uint64(data[0:8]),
		Slot:      binary.BigEndian.Uint64(data[8:16]),
		BlobIndex: int(binary.BigEndian.Uint32(data[16:20])),
		CellRow:   int(binary.BigEndian.Uint32(data[20:24])),
		CellCol:   int(binary.BigEndian.Uint32(data[24:28])),
	}, nil
}

// P1-12 (RPC-H1, 2026-07-19): Response layout mirrors the request header
// (RequestID at offset 0) so the requester can dispatch by RequestID:
//
//	[0:8)   RequestID  (uint64)
//	[8:16)  Slot       (uint64)
//	[16:20) BlobIndex  (uint32)
//	[20:24) CellRow    (uint32)
//	[24:28) CellCol    (uint32)
//	[28:28+CellSize) Cell
//	[28+CellSize:28+CellSize+48) Proof
func encodeDASSampleResponse(resp DASSampleResponse) []byte {
	buf := make([]byte, DASSampleResponseSize)
	binary.BigEndian.PutUint64(buf[0:8], resp.RequestID)
	binary.BigEndian.PutUint64(buf[8:16], resp.Slot)
	binary.BigEndian.PutUint32(buf[16:20], uint32(resp.BlobIndex))
	binary.BigEndian.PutUint32(buf[20:24], uint32(resp.CellRow))
	binary.BigEndian.PutUint32(buf[24:28], uint32(resp.CellCol))
	copy(buf[28:28+CellSize], resp.Cell[:])
	copy(buf[28+CellSize:], resp.Proof[:])
	return buf
}

func decodeDASSampleResponse(data []byte) (*DASSampleResponse, error) {
	if len(data) < DASSampleResponseSize {
		return nil, fmt.Errorf("data too short: got %d, want %d", len(data), DASSampleResponseSize)
	}
	resp := &DASSampleResponse{
		RequestID: binary.BigEndian.Uint64(data[0:8]),
		Slot:      binary.BigEndian.Uint64(data[8:16]),
		BlobIndex: int(binary.BigEndian.Uint32(data[16:20])),
		CellRow:   int(binary.BigEndian.Uint32(data[20:24])),
		CellCol:   int(binary.BigEndian.Uint32(data[24:28])),
	}
	copy(resp.Cell[:], data[28:28+CellSize])
	copy(resp.Proof[:], data[28+CellSize:28+CellSize+48])
	return resp, nil
}

type BlobGarbageCollector struct {
	storage *BlobStorage
	ticker  *time.Ticker
	done    chan struct{}
	getSlot func() uint64
	// P3-1 (2026-07-15): Optional callback invoked after each GC cycle
	// (whether the ticker fired or the engine triggered a manual GC via
	// CleanupOldData). Used by the DankshardingEngine to increment the
	// da_gc_cycles_total Prometheus counter. Nil-safe: when not set, the
	// GC proceeds normally without the callback.
	onGC func()
	// stopOnce makes Stop() idempotent: close(done) happens at most once.
	// R59 (2026-08-18): DankshardingEngine.Stop() AND Shutdown() both call
	// gc.Stop(), and node.go has two shutdown paths that call
	// n.danksharding.Stop() (cleanupPartialInit followed by a normal
	// Stop()). Without this guard, a second Stop() would close an already
	// closed channel and panic the node mid-shutdown.
	stopOnce sync.Once
}

// SetOnGC registers a callback invoked after each GC cycle. P3-1 (2026-07-15).
// The callback is invoked from the GC ticker goroutine (for automatic cycles)
// — implementations MUST be safe to call from a different goroutine.
func (gc *BlobGarbageCollector) SetOnGC(fn func()) {
	gc.storage.mu.Lock() // reuse storage's mutex to protect the onGC field
	defer gc.storage.mu.Unlock()
	gc.onGC = fn
}

func NewBlobGarbageCollector(storage *BlobStorage, getSlot func() uint64) *BlobGarbageCollector {
	interval := BlobGCTickerInterval
	if storage != nil {
		storage.mu.RLock()
		interval = storage.retention.GCTickerInterval
		storage.mu.RUnlock()
	}
	return &BlobGarbageCollector{
		storage: storage,
		ticker:  time.NewTicker(interval),
		done:    make(chan struct{}),
		getSlot: getSlot,
	}
}

func (gc *BlobGarbageCollector) Start() {
	// P3-1 (2026-07-15): Read the onGC callback once before the goroutine
	// starts. SetOnGC must be called before Start — calling it after Start
	// will not take effect. This avoids a data race between SetOnGC (which
	// writes under storage.mu.Lock) and the ticker goroutine reading onGC.
	onGC := gc.onGC
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Blob GC goroutine panic: %v\n", r)
			}
		}()
		for {
			select {
			case <-gc.ticker.C:
				if gc.getSlot != nil {
					currentSlot := gc.getSlot()
					gc.storage.GC(currentSlot)
					// P3-1 (2026-07-15): Notify callback (if registered)
					// so the engine can increment the GC cycles counter.
					if onGC != nil {
						onGC()
					}
				}
			case <-gc.done:
				return
			}
		}
	}()
}

func (gc *BlobGarbageCollector) Stop() {
	// R59 (2026-08-18): Idempotent — safe to call multiple times (e.g.
	// DankshardingEngine.Stop() followed by Shutdown(), or two node
	// shutdown paths). Without the Once guard a second call would
	// close(gc.done) again and panic.
	gc.stopOnce.Do(func() {
		gc.ticker.Stop()
		close(gc.done)
	})
}

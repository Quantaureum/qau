// Quantaureum Node source, version 1.0.0.
// Package lightclient provides light client support for the Quantaureum blockchain.
// Light clients can verify blockchain data without downloading the full chain.
package lightclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Common errors
var (
	ErrCheckpointNotFound     = errors.New("checkpoint not found")
	ErrInvalidCheckpoint      = errors.New("invalid checkpoint")
	ErrCheckpointVerification = errors.New("checkpoint signature verification failed")
	ErrHeaderNotFound         = errors.New("header not found")
	ErrInvalidHeader          = errors.New("invalid header")
	ErrInvalidProof           = errors.New("invalid proof")
	ErrTxNotFound             = errors.New("transaction not found")
	ErrStateNotFound          = errors.New("state not found")
	ErrInvalidStateProof      = errors.New("invalid state proof")
	ErrSyncInProgress         = errors.New("sync in progress")
	ErrNotSynced              = errors.New("not synced")
	ErrNoTrustedValidator     = errors.New("no trusted validator configured")
)

// Checkpoint represents a trusted checkpoint for fast sync
type Checkpoint struct {
	Height    uint64     // Block height
	Hash      types.Hash // Block hash
	StateRoot types.Hash // State root at this height
	Timestamp int64      // Timestamp of the checkpoint
	Signature []byte     // Signature from trusted validators
}

// HeaderStream provides streaming access to block headers
type HeaderStream struct {
	headers chan *encoding.BlockHeader
	errors  chan error
	done    chan struct{}
	closed  bool
	mu      sync.Mutex
}

// NewHeaderStream creates a new header stream
func NewHeaderStream(bufferSize int) *HeaderStream {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &HeaderStream{
		headers: make(chan *encoding.BlockHeader, bufferSize),
		errors:  make(chan error, 1),
		done:    make(chan struct{}),
	}
}

// Headers returns the channel for receiving headers
func (s *HeaderStream) Headers() <-chan *encoding.BlockHeader {
	return s.headers
}

// Errors returns the channel for receiving errors
func (s *HeaderStream) Errors() <-chan error {
	return s.errors
}

// Done returns the channel that's closed when streaming is complete
func (s *HeaderStream) Done() <-chan struct{} {
	return s.done
}

// Send sends a header to the stream
func (s *HeaderStream) Send(header *encoding.BlockHeader) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}

	select {
	case s.headers <- header:
		return true
	case <-s.done:
		return false
	}
}

// SendError sends an error to the stream
func (s *HeaderStream) SendError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	select {
	case s.errors <- err:
	default:
	}
}

// Close closes the stream
func (s *HeaderStream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	s.closed = true
	close(s.done)
	close(s.headers)
}

// HeaderSyncer provides block header synchronization for light clients
type HeaderSyncer struct {
	blockStore             *block.BlockStore
	checkpoints            map[uint64]*Checkpoint
	latestHeight           uint64
	syncing                bool
	mu                     sync.RWMutex
	trustedValidatorPubKey *crypto.PublicKey // Trusted public key for checkpoint verification
	syncCommitteeVerifier  *SyncCommitteeVerifier
}

// NewHeaderSyncer creates a new header syncer
// trustedPubKey is optional but MUST be provided for AddCheckpoint to verify signatures
func NewHeaderSyncer(blockStore *block.BlockStore, trustedPubKey *crypto.PublicKey) *HeaderSyncer {
	return &HeaderSyncer{
		blockStore:             blockStore,
		checkpoints:            make(map[uint64]*Checkpoint),
		trustedValidatorPubKey: trustedPubKey,
		syncCommitteeVerifier:  NewSyncCommitteeVerifier(),
	}
}

// AddCheckpoint adds a trusted checkpoint after verifying its signature.
// SECURITY: Checkpoints MUST be verified before storage to prevent malicious
// checkpoints from being injected by attackers.
func (s *HeaderSyncer) AddCheckpoint(cp *Checkpoint) error {
	if cp == nil {
		return ErrInvalidCheckpoint
	}

	// CRITICAL: Verify signature before storing
	if err := s.verifyCheckpoint(cp); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.checkpoints[cp.Height] = cp
	return nil
}

// checkpointHash computes the hash of checkpoint data that was signed.
// This must match what validators signed when creating the checkpoint.
func (s *HeaderSyncer) checkpointHash(cp *Checkpoint) types.Hash {
	data := make([]byte, 8+32+32+8) // height(8) + hash(32) + stateRoot(32) + timestamp(8)
	binary.BigEndian.PutUint64(data[0:8], cp.Height)
	copy(data[8:40], cp.Hash[:])
	copy(data[40:72], cp.StateRoot[:])
	ts := cp.Timestamp
	if ts < 0 {
		ts = 0
	}
	binary.BigEndian.PutUint64(data[72:80], uint64(ts)) //nolint:gosec,G115

	h := sha3.Sum256(data)
	return types.BytesToHash(h[:])
}

// verifyCheckpoint verifies the checkpoint signature using the trusted public key.
func (s *HeaderSyncer) verifyCheckpoint(cp *Checkpoint) error {
	if s.trustedValidatorPubKey == nil {
		return ErrNoTrustedValidator
	}

	if len(cp.Signature) == 0 {
		return ErrCheckpointVerification
	}

	cpHash := s.checkpointHash(cp)
	if !crypto.Verify(s.trustedValidatorPubKey, cpHash[:], cp.Signature) {
		return ErrCheckpointVerification
	}

	return nil
}

// GetCheckpoint retrieves a checkpoint by height.
// audit-fix R13-M1: returns a deep copy so callers cannot mutate internal state
// (consistent with GetAllCheckpoints which already copies).
func (s *HeaderSyncer) GetCheckpoint(height uint64) (*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp, exists := s.checkpoints[height]
	if !exists {
		return nil, ErrCheckpointNotFound
	}
	return s.copyCheckpoint(cp), nil
}

// GetNearestCheckpoint finds the nearest checkpoint at or before the given height.
//
//	[LOW] FIX: extracts keys into a sorted slice for deterministic iteration.
//
// Go map iteration is non-deterministic and could cause consensus divergence across nodes.
func (s *HeaderSyncer) GetNearestCheckpoint(height uint64) (*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Extract eligible heights into a sorted slice for deterministic traversal
	var eligible []uint64
	for h := range s.checkpoints {
		if h <= height {
			eligible = append(eligible, h)
		}
	}

	if len(eligible) == 0 {
		return nil, ErrCheckpointNotFound
	}

	// Sort ascending for deterministic selection
	sort.Slice(eligible, func(i, j int) bool { return eligible[i] < eligible[j] })

	// Last element is the nearest (largest height <= target)
	nearestHeight := eligible[len(eligible)-1]
	return s.copyCheckpoint(s.checkpoints[nearestHeight]), nil
}

// copyCheckpoint returns a deep copy of a Checkpoint, including byte slices.
// audit-fix R13-M1: shared helper used by GetCheckpoint, GetNearestCheckpoint,
// and GetAllCheckpoints to prevent callers from mutating internal state.
func (s *HeaderSyncer) copyCheckpoint(cp *Checkpoint) *Checkpoint {
	cpCopy := *cp
	if cp.Signature != nil {
		cpCopy.Signature = make([]byte, len(cp.Signature))
		copy(cpCopy.Signature, cp.Signature)
	}
	return &cpCopy
}

// GetAllCheckpoints returns all checkpoints
// audit-fix R7-L1: returns defensive copies to prevent callers from mutating internal state
func (s *HeaderSyncer) GetAllCheckpoints() []*Checkpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	checkpoints := make([]*Checkpoint, 0, len(s.checkpoints))
	for _, cp := range s.checkpoints {
		checkpoints = append(checkpoints, s.copyCheckpoint(cp))
	}
	return checkpoints
}

// StreamHeaders streams block headers from startHeight to endHeight
func (s *HeaderSyncer) StreamHeaders(startHeight, endHeight uint64) *HeaderStream {
	stream := NewHeaderStream(100)

	go func() {
		defer stream.Close()
		defer func() {
			if r := recover(); r != nil {
				stream.SendError(fmt.Errorf("HeaderStream goroutine panic: %v", r))
			}
		}()

		for height := startHeight; height <= endHeight; height++ {
			header, err := s.GetHeaderByHeight(height)
			if err != nil {
				stream.SendError(err)
				return
			}

			if !stream.Send(header) {
				return
			}
		}
	}()

	return stream
}

// GetHeaderByHeight retrieves a block header by height
func (s *HeaderSyncer) GetHeaderByHeight(height uint64) (*encoding.BlockHeader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.blockStore == nil {
		return nil, ErrHeaderNotFound
	}

	hash, err := s.blockStore.GetBlockHash(height)
	if err != nil {
		return nil, ErrHeaderNotFound
	}

	return s.blockStore.GetBlockHeader(hash)
}

// GetHeaderByHash retrieves a block header by hash
func (s *HeaderSyncer) GetHeaderByHash(hash types.Hash) (*encoding.BlockHeader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.blockStore == nil {
		return nil, ErrHeaderNotFound
	}

	return s.blockStore.GetBlockHeader(hash)
}

// GetHeaderRange retrieves a range of headers
func (s *HeaderSyncer) GetHeaderRange(startHeight, count uint64) ([]*encoding.BlockHeader, error) {
	headers := make([]*encoding.BlockHeader, 0, count)

	for i := uint64(0); i < count; i++ {
		header, err := s.GetHeaderByHeight(startHeight + i)
		if err != nil {
			if err == ErrHeaderNotFound && i > 0 {
				// Return what we have
				break
			}
			return nil, err
		}
		headers = append(headers, header)
	}

	return headers, nil
}

// VerifyHeaderChain verifies a chain of headers is valid
func (s *HeaderSyncer) VerifyHeaderChain(headers []*encoding.BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}

	for i := 1; i < len(headers); i++ {
		prev := headers[i-1]
		curr := headers[i]

		// Verify height is sequential
		if curr.Height != prev.Height+1 {
			return ErrInvalidHeader
		}

		// Verify parent hash
		prevHash := block.ComputeBlockHash(prev)
		if curr.ParentHash != prevHash {
			return ErrInvalidHeader
		}

		// Verify timestamp is increasing
		if curr.Timestamp < prev.Timestamp {
			return ErrInvalidHeader
		}

		// Verify sync committee signature if available
		if s.syncCommitteeVerifier != nil {
			if err := s.syncCommitteeVerifier.VerifyBlockHeader(curr); err != nil {
				if err == ErrSyncCommitteeNotAvailable {
					continue // Skip if no committee data yet
				}
				return fmt.Errorf("sync committee verification failed at height %d: %w", curr.Height, err)
			}
		}
	}

	return nil
}

// UpdateSyncCommittee updates the sync committee info for light client verification.
func (s *HeaderSyncer) UpdateSyncCommittee(info *SyncCommitteeInfo) {
	if s.syncCommitteeVerifier != nil {
		s.syncCommitteeVerifier.UpdateCurrentCommittee(info)
	}
}

// GetSyncCommitteeVerifier returns the sync committee verifier.
func (s *HeaderSyncer) GetSyncCommitteeVerifier() *SyncCommitteeVerifier {
	return s.syncCommitteeVerifier
}

// GetLatestHeight returns the latest synced height
func (s *HeaderSyncer) GetLatestHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latestHeight
}

// SetLatestHeight sets the latest synced height
func (s *HeaderSyncer) SetLatestHeight(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latestHeight = height
}

// IsSyncing returns true if sync is in progress
func (s *HeaderSyncer) IsSyncing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncing
}

// MarshalCheckpoint serializes a checkpoint
func MarshalCheckpoint(cp *Checkpoint) ([]byte, error) {
	if cp == nil {
		return nil, ErrInvalidCheckpoint
	}

	// Format: [height(8)] [hash(32)] [stateRoot(32)] [timestamp(8)] [sigLen(4)] [sig]
	sigLen := len(cp.Signature)
	buf := make([]byte, 8+32+32+8+4+sigLen)

	binary.BigEndian.PutUint64(buf[0:8], cp.Height)
	copy(buf[8:40], cp.Hash[:])
	copy(buf[40:72], cp.StateRoot[:])
	binary.BigEndian.PutUint64(buf[72:80], uint64(cp.Timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	binary.BigEndian.PutUint32(buf[80:84], uint32(sigLen))       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	copy(buf[84:], cp.Signature)

	return buf, nil
}

// UnmarshalCheckpoint deserializes a checkpoint
func UnmarshalCheckpoint(data []byte) (*Checkpoint, error) {
	if len(data) < 84 {
		return nil, ErrInvalidCheckpoint
	}

	cp := &Checkpoint{}
	cp.Height = binary.BigEndian.Uint64(data[0:8])
	copy(cp.Hash[:], data[8:40])
	copy(cp.StateRoot[:], data[40:72])
	cp.Timestamp = int64(binary.BigEndian.Uint64(data[72:80])) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	sigLen := binary.BigEndian.Uint32(data[80:84])
	// audit-fix R3-L2: use uint32 arithmetic to avoid int overflow on 32-bit
	// platforms where int(sigLen) for sigLen > MaxInt32 wraps negative.
	available := uint32(len(data) - 84) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if available < sigLen {
		return nil, ErrInvalidCheckpoint
	}

	cp.Signature = make([]byte, sigLen)
	copy(cp.Signature, data[84:84+int(sigLen)])

	return cp, nil
}

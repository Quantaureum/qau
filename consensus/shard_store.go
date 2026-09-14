// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// Key prefixes for shard state persistence. Each prefix is combined with
// shardID (and optionally a secondary key) to form the full database key.
// This keeps shard state isolated from other database users (accounts,
// storage, commitments, etc.).
var (
	shardBlockPrefix   = []byte("shard_blk:") // shard_blk:{shardID}:{height} → ShardBlock (JSON)
	shardCommitPrefix  = []byte("shard_cmt:") // shard_cmt:{shardID}:{height} → 32 bytes (types.Hash)
	shardReceiptPrefix = []byte("shard_rcp:") // shard_rcp:{shardID}:{msgID}  → CrossShardReceipt (JSON)
	shardSpentPrefix   = []byte("shard_spt:") // shard_spt:{shardID}:{msgID}  → 1 byte (presence)
	shardNoncePrefix   = []byte("shard_non:") // shard_non:{shardID}:{addr}   → 8 bytes (uint64 LE)
	shardLatestPrefix  = []byte("shard_lat:") // shard_lat:{shardID}          → 8 bytes (uint64 LE)
	shardAssignPrefix  = []byte("shard_asg:") // shard_asg:{shardID}          → ShardValidatorAssignment (JSON) [P1-4]
)

// ShardStateStore provides persistence for shard chain state using a
// db.Database backend. It implements a write-through cache pattern: the
// in-memory maps in ShardChain remain the primary data structure for reads,
// and ShardStateStore persists mutations for crash recovery.
//
// P0-3 (2026-07-13): Previously, all shard state (blocks, commitments,
// receipts, spentReceipts, senderNonces) was purely in-memory. A node
// restart would lose all state, including the HIGH-17 replay protection
// (spentReceipts and senderNonces). This store ensures that critical state
// survives restarts.
//
// Design:
//   - Simple values (commitments, nonces, spent markers, latest height)
//     use manual binary encoding for efficiency.
//   - Complex structures (ShardBlock, CrossShardReceipt) use JSON encoding
//     for maintainability and forward-compatibility.
//   - Writes are synchronous (Put is atomic in BoltDB). For batch writes,
//     use NewBatch if performance becomes a concern.
type ShardStateStore struct {
	mu       sync.RWMutex
	database db.Database
}

// NewShardStateStore creates a new ShardStateStore backed by the given
// database. The database must be non-nil for production use.
func NewShardStateStore(database db.Database) *ShardStateStore {
	return &ShardStateStore{database: database}
}

// Database returns the underlying database. Used by ShardChain for direct
// access when needed (e.g., MainChainCommitterImpl integration).
func (s *ShardStateStore) Database() db.Database {
	return s.database
}

// --- ShardBlock persistence ---

// PutBlock persists a shard block keyed by (shardID, height).
func (s *ShardStateStore) PutBlock(shardID uint64, block *ShardBlock) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if block == nil || block.Header == nil {
		return fmt.Errorf("nil block or header")
	}
	data, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal shard block: %w", err)
	}
	key := shardBlockKey(shardID, block.Header.Height)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, data)
}

// GetBlock retrieves a shard block by (shardID, height).
// Returns nil, nil if the block is not found.
func (s *ShardStateStore) GetBlock(shardID, height uint64) (*ShardBlock, error) {
	if s == nil || s.database == nil {
		return nil, ErrStateStoreNotConfigured
	}
	key := shardBlockKey(shardID, height)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read shard block: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var block ShardBlock
	if err := json.Unmarshal(data, &block); err != nil {
		return nil, fmt.Errorf("failed to unmarshal shard block: %w", err)
	}
	return &block, nil
}

// --- Commitment persistence ---

// PutCommitment persists a commitment hash keyed by (shardID, height).
func (s *ShardStateStore) PutCommitment(shardID, height uint64, commitment types.Hash) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	key := shardStoreCommitKey(shardID, height)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, commitment[:])
}

// GetCommitment retrieves a commitment hash by (shardID, height).
// Returns (types.Hash{}, false, nil) if not found.
func (s *ShardStateStore) GetCommitment(shardID, height uint64) (types.Hash, bool, error) {
	if s == nil || s.database == nil {
		return types.Hash{}, false, ErrStateStoreNotConfigured
	}
	key := shardStoreCommitKey(shardID, height)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return types.Hash{}, false, nil
		}
		return types.Hash{}, false, fmt.Errorf("failed to read commitment: %w", err)
	}
	if len(data) < 32 {
		return types.Hash{}, false, nil
	}
	var hash types.Hash
	copy(hash[:], data[:32])
	return hash, true, nil
}

// --- Receipt persistence ---

// PutReceipt persists a cross-shard receipt keyed by (shardID, messageID).
func (s *ShardStateStore) PutReceipt(shardID uint64, msgID types.Hash, receipt *CrossShardReceipt) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if receipt == nil {
		return fmt.Errorf("nil receipt")
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}
	key := shardReceiptKey(shardID, msgID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, data)
}

// GetReceipt retrieves a cross-shard receipt by (shardID, messageID).
// Returns nil, nil if not found.
func (s *ShardStateStore) GetReceipt(shardID uint64, msgID types.Hash) (*CrossShardReceipt, error) {
	if s == nil || s.database == nil {
		return nil, ErrStateStoreNotConfigured
	}
	key := shardReceiptKey(shardID, msgID)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read receipt: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var receipt CrossShardReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal receipt: %w", err)
	}
	return &receipt, nil
}

// --- Spent receipt persistence ---

// MarkReceiptSpent marks a receipt as spent for the given shard.
func (s *ShardStateStore) MarkReceiptSpent(shardID uint64, msgID types.Hash) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	key := shardSpentKey(shardID, msgID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, []byte{0x01})
}

// IsReceiptSpent checks if a receipt has been spent for the given shard.
func (s *ShardStateStore) IsReceiptSpent(shardID uint64, msgID types.Hash) (bool, error) {
	if s == nil || s.database == nil {
		return false, ErrStateStoreNotConfigured
	}
	key := shardSpentKey(shardID, msgID)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if err == db.ErrKeyNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check spent receipt: %w", err)
	}
	return len(data) > 0 && data[0] == 0x01, nil
}

// --- Nonce persistence ---

// PutSenderNonce persists the latest nonce for a sender on a shard.
func (s *ShardStateStore) PutSenderNonce(shardID uint64, sender types.Address, nonce uint64) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	key := shardNonceKey(shardID, sender)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], nonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, buf[:])
}

// GetSenderNonce retrieves the latest nonce for a sender on a shard.
// Returns (0, false, nil) if not found.
func (s *ShardStateStore) GetSenderNonce(shardID uint64, sender types.Address) (uint64, bool, error) {
	if s == nil || s.database == nil {
		return 0, false, ErrStateStoreNotConfigured
	}
	key := shardNonceKey(shardID, sender)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if err == db.ErrKeyNotFound {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("failed to read sender nonce: %w", err)
	}
	if len(data) < 8 {
		return 0, false, nil
	}
	return binary.LittleEndian.Uint64(data[:8]), true, nil
}

// --- Latest height persistence ---

// PutLatestHeight persists the latest block height for a shard.
func (s *ShardStateStore) PutLatestHeight(shardID, height uint64) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	key := shardLatestKey(shardID)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], height)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, buf[:])
}

// GetLatestHeight retrieves the latest block height for a shard.
// Returns (0, false, nil) if not found.
func (s *ShardStateStore) GetLatestHeight(shardID uint64) (uint64, bool, error) {
	if s == nil || s.database == nil {
		return 0, false, ErrStateStoreNotConfigured
	}
	key := shardLatestKey(shardID)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if err == db.ErrKeyNotFound {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("failed to read latest height: %w", err)
	}
	if len(data) < 8 {
		return 0, false, nil
	}
	return binary.LittleEndian.Uint64(data[:8]), true, nil
}

// --- Validator assignment persistence (P1-4) ---
//
// P1-4 (2026-07-14): AssignValidatorsToShards and ReassignValidators
// persist their results to the store so all nodes read the same assignment
// table from the shared database. On startup, ShardManager.LoadAssignments
// restores the in-memory assignment map from these records.

// PutAssignment persists a shard validator assignment.
func (s *ShardStateStore) PutAssignment(shardID uint64, assignment *ShardValidatorAssignment) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	if assignment == nil {
		return fmt.Errorf("nil assignment")
	}
	data, err := json.Marshal(assignment)
	if err != nil {
		return fmt.Errorf("failed to marshal shard assignment: %w", err)
	}
	key := shardAssignKey(shardID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Put(key, data)
}

// GetAssignment retrieves a shard validator assignment by shardID.
// Returns nil, nil if not found.
func (s *ShardStateStore) GetAssignment(shardID uint64) (*ShardValidatorAssignment, error) {
	if s == nil || s.database == nil {
		return nil, ErrStateStoreNotConfigured
	}
	key := shardAssignKey(shardID)
	s.mu.RLock()
	data, err := s.database.Get(key)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read shard assignment: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var assignment ShardValidatorAssignment
	if err := json.Unmarshal(data, &assignment); err != nil {
		return nil, fmt.Errorf("failed to unmarshal shard assignment: %w", err)
	}
	return &assignment, nil
}

// GetAllAssignments iterates over all stored assignments. Used by
// ShardManager.LoadAssignments on startup to restore the in-memory map.
func (s *ShardStateStore) GetAllAssignments() (map[uint64]*ShardValidatorAssignment, error) {
	if s == nil || s.database == nil {
		return nil, ErrStateStoreNotConfigured
	}
	result := make(map[uint64]*ShardValidatorAssignment)
	s.mu.RLock()
	it := s.database.NewIterator(shardAssignPrefix, nil)
	s.mu.RUnlock()
	defer it.Release()
	for it.Next() {
		var assignment ShardValidatorAssignment
		if err := json.Unmarshal(it.Value(), &assignment); err != nil {
			return nil, fmt.Errorf("failed to unmarshal shard assignment: %w", err)
		}
		result[assignment.ShardID] = &assignment
	}
	if err := it.Error(); err != nil {
		return nil, fmt.Errorf("iterator error: %w", err)
	}
	return result, nil
}

// DeleteAssignment removes a shard validator assignment. Used when a shard
// is permanently deactivated and its assignment record is no longer needed.
func (s *ShardStateStore) DeleteAssignment(shardID uint64) error {
	if s == nil || s.database == nil {
		return ErrStateStoreNotConfigured
	}
	key := shardAssignKey(shardID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.database.Delete(key)
}

// --- Key builders ---

func shardBlockKey(shardID, height uint64) []byte {
	return buildKey(shardBlockPrefix, shardID, heightBytes(height))
}

func shardStoreCommitKey(shardID, height uint64) []byte {
	return buildKey(shardCommitPrefix, shardID, heightBytes(height))
}

func shardReceiptKey(shardID uint64, msgID types.Hash) []byte {
	return buildKey(shardReceiptPrefix, shardID, msgID[:])
}

func shardSpentKey(shardID uint64, msgID types.Hash) []byte {
	return buildKey(shardSpentPrefix, shardID, msgID[:])
}

func shardNonceKey(shardID uint64, addr types.Address) []byte {
	return buildKey(shardNoncePrefix, shardID, addr[:])
}

func shardLatestKey(shardID uint64) []byte {
	return buildKey(shardLatestPrefix, shardID, nil)
}

func shardAssignKey(shardID uint64) []byte {
	return buildKey(shardAssignPrefix, shardID, nil)
}

// buildKey constructs a database key from a prefix, shardID, and optional
// suffix. Format: prefix + shardID(8 bytes LE) + suffix
func buildKey(prefix []byte, shardID uint64, suffix []byte) []byte {
	key := make([]byte, 0, len(prefix)+8+len(suffix))
	key = append(key, prefix...)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], shardID)
	key = append(key, buf[:]...)
	key = append(key, suffix...)
	return key
}

func heightBytes(height uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], height)
	return buf[:]
}

// ErrStateStoreNotConfigured is returned when the store is used before
// its database is configured.
var ErrStateStoreNotConfigured = fmt.Errorf("shard state store not configured: database is nil")

// Quantaureum Node source, version 1.0.0.
// Package bridge implements persistent storage for cross-chain bridge messages.
// P0-6 FIX (2026-07-13): bridge message persistence.
//
// Previously QuantumBridge kept messages, usedNonces, finalizedIDs only in memory;
// after a node restart all PENDING/VERIFIED messages were lost, opening a replay window
// (attackers could reuse old nonces to resubmit already-executed messages).
//
// This file implements the MessageStore interface with bbolt:
//   - messages bucket: key = message ID, value = JSON-serialized BridgeMessage
//   - status_index bucket: key = status || messageID, value = empty (status index)
//
// Error handling and security constraints match qaudb/db/boltdb.go (0600 permissions, write-back verification, etc.).
package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// BoltMessageStore is the bbolt-based MessageStore implementation.
// P0-6 FIX (2026-07-13): replaces the memory-only mode so bridge state survives restarts.
//
// Security constraints:
//   - db file mode 0600 (owner-only read/write)
//   - parent directory mode 0700
//   - all writes happen in Update transactions, auto-persisted
//   - all reads happen in View transactions, side-effect free
//
// Concurrency: bbolt internally uses a file lock + read/write transaction isolation; multiple goroutines can safely share
// one *BoltMessageStore instance. QuantumBridge calls store methods while holding q.mu
// inside SubmitMessage/ProcessMessage, further guaranteeing consistency.
type BoltMessageStore struct {
	db   *bolt.DB
	path string
}

// bbolt bucket names. []byte constants avoid per-call allocation.
var (
	msgBucket            = []byte("bridge_messages")
	statusBucket         = []byte("bridge_status_index")
	nonceHighwaterBucket = []byte("bridge_nonce_highwater") // R32-P1-04 FIX (2026-07-28): dedicated high-water-mark persistence
)

// NewBoltMessageStore opens (or creates) a bbolt file for persisting bridge messages.
//
// Parameters:
//   - dbPath: bbolt file path (with filename); the parent directory is auto-created (mode 0700)
//
// The caller owns the returned *BoltMessageStore and must Close() it (usually inside QuantumBridge.Stop()).
//
// Error handling:
//   - parent-directory creation failure: error
//   - bbolt open failure (5 retries, exponential backoff): error
//   - bucket creation failure: close the db and return an error
func NewBoltMessageStore(dbPath string) (*BoltMessageStore, error) {
	// SECURITY: 0700 restricts the parent directory to the owner
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("message_store: create dir %s: %w", dir, err)
	}

	var bdb *bolt.DB
	var err error
	// 5 retries, consistent with qaudb/db/boltdb.go
	for attempt := 0; attempt < 5; attempt++ {
		bdb, err = bolt.Open(dbPath, 0600, &bolt.Options{
			NoFreelistSync: false,
			Timeout:        30 * time.Second,
			NoGrowSync:     false,
		})
		if err == nil {
			break
		}
		if attempt < 4 {
			time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("message_store: open %s after 5 attempts (may be locked): %w", dbPath, err)
	}

	// ensure both buckets exist
	if err := bdb.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(msgBucket); err != nil {
			return fmt.Errorf("create messages bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(statusBucket); err != nil {
			return fmt.Errorf("create status_index bucket: %w", err)
		}
		// R32-P1-04 FIX (2026-07-28): dedicated bucket for highestUsedNonce
		// persistence. Survives even if EXECUTED messages are pruned from
		// the message store in the future.
		if _, err := tx.CreateBucketIfNotExists(nonceHighwaterBucket); err != nil {
			return fmt.Errorf("create nonce_highwater bucket: %w", err)
		}
		return nil
	}); err != nil {
		if closeErr := bdb.Close(); closeErr != nil {
			// P3-3 (2026-07-15): structured log replaces log.Printf.
			pkgLogger.Warn("message_store Close error after bucket creation failure", Field{"error", closeErr.Error()})
		}
		return nil, err
	}

	return &BoltMessageStore{db: bdb, path: dbPath}, nil
}

// Close closes the underlying bbolt database. Safe to call multiple times (bbolt is idempotent).
// Must be called inside QuantumBridge.Stop() to flush unwritten data.
func (s *BoltMessageStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the bbolt file path, for logging/diagnostics.
func (s *BoltMessageStore) Path() string {
	return s.path
}

// SaveMessage writes one bridge message into persistent storage.
//
// Behavior:
//   - fully serializes the BridgeMessage to JSON (all fields: signatures, public keys, status, etc.)
//   - writes into the messages bucket (key = msg.ID)
//   - updates the status_index bucket in sync (delete the ID's index under every status first, then write the new status)
//     keeping status_index always consistent with the messages bucket's status field
//
// Error handling:
//   - nil msg: error (defensive)
//   - empty msg.ID: error (cannot be indexed)
//   - JSON serialization failure: error
//   - bbolt write failure: error (transaction rolled back, no side effects)
//
// Note: this method is idempotent — re-saving the same ID overwrites the old value.
// That is intentional: SubmitMessage already rejects duplicate IDs at the memory layer.
func (s *BoltMessageStore) SaveMessage(ctx context.Context, msg *BridgeMessage) error {
	if msg == nil {
		return fmt.Errorf("message_store: SaveMessage nil message")
	}
	if msg.ID == "" {
		return fmt.Errorf("message_store: SaveMessage empty message ID")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("message_store: marshal message %s: %w", msg.ID, err)
	}

	statusKey := statusIndexKey(msg.Status, msg.ID)

	return s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(msgBucket)
		if mb == nil {
			return fmt.Errorf("message_store: bucket %q not found", msgBucket)
		}
		sb := tx.Bucket(statusBucket)
		if sb == nil {
			return fmt.Errorf("message_store: bucket %q not found", statusBucket)
		}

		// delete the old status index first (a message may move PENDING → VERIFIED; the old PENDING index must go)
		if err := removeStatusIndex(sb, msg.ID); err != nil {
			return fmt.Errorf("remove old status index for %s: %w", msg.ID, err)
		}

		// write the message
		if err := mb.Put([]byte(msg.ID), data); err != nil {
			return fmt.Errorf("put message %s: %w", msg.ID, err)
		}

		// write-back verification (consistent with qaudb/db/boltdb.go Put)
		written := mb.Get([]byte(msg.ID))
		if written == nil {
			return fmt.Errorf("write-back verification failed: message %s not found after write", msg.ID)
		}
		if len(written) != len(data) {
			return fmt.Errorf("write-back verification failed: message %s size mismatch", msg.ID)
		}

		// write the new status index
		if err := sb.Put(statusKey, []byte{}); err != nil {
			return fmt.Errorf("put status index for %s: %w", msg.ID, err)
		}

		return nil
	})
}

// LoadMessage loads one message by ID.
//
// Returns:
//   - found: the deserialized *BridgeMessage, nil
//   - not found: nil, ErrMessageNotFound
//   - other error: nil, err
func (s *BoltMessageStore) LoadMessage(ctx context.Context, id string) (*BridgeMessage, error) {
	if id == "" {
		return nil, fmt.Errorf("message_store: LoadMessage empty ID")
	}

	var data []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket(msgBucket)
		if mb == nil {
			return fmt.Errorf("message_store: bucket %q not found", msgBucket)
		}
		v := mb.Get([]byte(id))
		if v == nil {
			return ErrMessageNotFound
		}
		// must copy; bbolt return values are invalid after the transaction ends
		data = make([]byte, len(v))
		copy(data, v)
		return nil
	}); err != nil {
		return nil, err
	}

	var msg BridgeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("message_store: unmarshal message %s: %w", id, err)
	}
	return &msg, nil
}

// LoadMessagesByStatus loads all messages with a given status.
//
// Implementation: prefix-scan status||messageID in the status_index bucket, then fetch by ID from the messages bucket.
// This avoids a full scan of the messages bucket with per-message status filtering.
//
// Returns:
//   - N found: a slice (possibly length 0), nil
//   - missing bucket: nil, err
//   - a message failing to deserialize: skip it, log, continue with the rest
//     (one corrupt message must not block the whole startup)
func (s *BoltMessageStore) LoadMessagesByStatus(ctx context.Context, status BridgeMessageStatus) ([]*BridgeMessage, error) {
	prefix := []byte(string(status) + statusKeySep)

	var messages []*BridgeMessage
	err := s.db.View(func(tx *bolt.Tx) error {
		mb := tx.Bucket(msgBucket)
		if mb == nil {
			return fmt.Errorf("message_store: bucket %q not found", msgBucket)
		}
		sb := tx.Bucket(statusBucket)
		if sb == nil {
			return fmt.Errorf("message_store: bucket %q not found", statusBucket)
		}

		c := sb.Cursor()
		// cap the scan count, preventing OOM from malicious/corrupt data
		// matches maxIterations in qaudb/db/boltdb.go NewIterator
		const maxIterations = 100000
		iterCount := 0

		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if iterCount >= maxIterations {
				// P3-3 (2026-07-15): structured log replaces log.Printf.
				pkgLogger.Warn("message_store LoadMessagesByStatus hit max iteration limit",
					Field{"limit", maxIterations},
					Field{"status", string(status)})
				break
			}
			iterCount++

			// extract the messageID from status||messageID
			msgID := extractMsgIDFromStatusKey(k, status)
			if msgID == "" {
				continue
			}

			v := mb.Get([]byte(msgID))
			if v == nil {
				// status_index references a missing message — inconsistent data
				// log but do not error; one bad index must not block startup
				// P3-3 (2026-07-15): structured log replaces log.Printf.
				pkgLogger.Warn("message_store status_index points to missing message (data inconsistency)",
					Field{"message_id", msgID})
				continue
			}

			var msg BridgeMessage
			if err := json.Unmarshal(v, &msg); err != nil {
				// skip the corrupt message and log
				// P3-3 (2026-07-15): structured log replaces log.Printf.
				pkgLogger.Error("message_store unmarshal message failed (skipping)",
					Field{"message_id", msgID},
					Field{"error", err.Error()})
				continue
			}
			messages = append(messages, &msg)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return messages, nil
}

// UpdateMessageStatus atomically updates message status (optimistic lock: fails if oldStatus doesn't match).
//
// Flow:
//  1. load the current message and verify Status == oldStatus (CAS semantics)
//  2. on mismatch: return ErrStatusMismatch (prevents concurrent overwrites)
//  3. on match: set Status = newStatus, re-serialize, write
//  4. update status_index: delete the (oldStatus, ID) index, write the (newStatus, ID) index
//
// Error handling:
//   - message missing: ErrMessageNotFound
//   - status mismatch: ErrStatusMismatch
//   - transaction failure: error (rolled back, no side effects)
//
// Note: the whole operation happens in one Update transaction, guaranteeing atomicity.
func (s *BoltMessageStore) UpdateMessageStatus(ctx context.Context, id string, oldStatus, newStatus BridgeMessageStatus) error {
	if id == "" {
		return fmt.Errorf("message_store: UpdateMessageStatus empty ID")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		mb := tx.Bucket(msgBucket)
		if mb == nil {
			return fmt.Errorf("message_store: bucket %q not found", msgBucket)
		}
		sb := tx.Bucket(statusBucket)
		if sb == nil {
			return fmt.Errorf("message_store: bucket %q not found", statusBucket)
		}

		// 1. load the current message
		v := mb.Get([]byte(id))
		if v == nil {
			return ErrMessageNotFound
		}

		// 2. deserialize and verify the status
		var msg BridgeMessage
		if err := json.Unmarshal(v, &msg); err != nil {
			return fmt.Errorf("message_store: unmarshal message %s for status update: %w", id, err)
		}
		if msg.Status != oldStatus {
			return fmt.Errorf("%w: message %s expected %s, got %s",
				ErrStatusMismatch, id, oldStatus, msg.Status)
		}

		// 3. update status and re-serialize
		msg.Status = newStatus
		newData, err := json.Marshal(&msg)
		if err != nil {
			return fmt.Errorf("message_store: marshal updated message %s: %w", id, err)
		}

		// 4. write the updated message
		if err := mb.Put([]byte(id), newData); err != nil {
			return fmt.Errorf("message_store: put updated message %s: %w", id, err)
		}

		// 5. update status_index: delete the old index, write the new one
		oldKey := statusIndexKey(oldStatus, id)
		newKey := statusIndexKey(newStatus, id)
		if err := sb.Delete(oldKey); err != nil {
			return fmt.Errorf("message_store: delete old status index for %s: %w", id, err)
		}
		if err := sb.Put(newKey, []byte{}); err != nil {
			return fmt.Errorf("message_store: put new status index for %s: %w", id, err)
		}

		return nil
	})
}

// SaveHighestUsedNonce persists the highest-used nonce for a (sourceChain,
// sourceAddress) pair.
//
// R32-P1-04 FIX (2026-07-28): Defense-in-depth persistence for the nonce
// high-water mark. Even though the bootstrap currently reconstructs
// highestUsedNonce from EXECUTED messages in the store, a dedicated bucket
// ensures the water mark survives future message-pruning features and
// provides O(1) lookups on restart instead of scanning all EXECUTED messages.
//
// Key format: sourceChain + "|" + sourceAddress
// Value: 8-byte big-endian uint64 nonce
func (s *BoltMessageStore) SaveHighestUsedNonce(ctx context.Context, sourceChain, sourceAddress string, nonce uint64) error {
	if sourceChain == "" || sourceAddress == "" {
		return fmt.Errorf("message_store: SaveHighestUsedNonce empty chain or address")
	}
	key := []byte(sourceChain + statusKeySep + sourceAddress)
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, nonce)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nonceHighwaterBucket)
		if b == nil {
			return fmt.Errorf("message_store: bucket %q not found", nonceHighwaterBucket)
		}
		return b.Put(key, val)
	})
}

// LoadAllHighestUsedNonces loads all persisted nonce high-water marks.
//
// R32-P1-04 FIX (2026-07-28): Returns a map keyed by NonceKey so the bridge
// can merge persisted values with reconstructed values on bootstrap, taking
// the max of each.
func (s *BoltMessageStore) LoadAllHighestUsedNonces(ctx context.Context) (map[NonceKey]uint64, error) {
	result := make(map[NonceKey]uint64)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nonceHighwaterBucket)
		if b == nil {
			// Bucket not created yet (legacy db file) — return empty map.
			return nil
		}
		c := b.Cursor()
		const maxIterations = 100000
		iterCount := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if iterCount >= maxIterations {
				pkgLogger.Warn("message_store LoadAllHighestUsedNonces hit max iteration limit",
					Field{"limit", maxIterations})
				break
			}
			iterCount++
			if len(v) != 8 {
				// Corrupted entry — skip with warning.
				pkgLogger.Warn("message_store nonce_highwater corrupted entry (size != 8)",
					Field{"key", string(k)})
				continue
			}
			// Split key: sourceChain + "|" + sourceAddress
			parts := bytes.SplitN(k, []byte(statusKeySep), 2)
			if len(parts) != 2 {
				pkgLogger.Warn("message_store nonce_highwater malformed key",
					Field{"key", string(k)})
				continue
			}
			nk := NonceKey{Chain: string(parts[0]), Addr: string(parts[1])}
			result[nk] = binary.BigEndian.Uint64(v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// === error definitions ===

// ErrMessageNotFound: message not found.
// Callers can use errors.Is to distinguish "missing" from "read failure".
var ErrMessageNotFound = fmt.Errorf("message not found in store")

// ErrStatusMismatch: optimistic-lock failure on status update (current status differs from expected oldStatus).
// This usually means another goroutine has already updated the message's status.
var ErrStatusMismatch = fmt.Errorf("message status mismatch")

// === internal helpers ===

// statusKeySep is the separator used in status-index keys.
// A single byte '|' avoids collisions in status strings (status values are uppercase-enum strings).
const statusKeySep = "|"

// statusIndexKey builds the status_index bucket key: status + "|" + messageID
//
// e.g. ("PENDING", "msg-123") → "PENDING|msg-123"
//
// Prefix-scanning by status then efficiently finds all message IDs under that status.
func statusIndexKey(status BridgeMessageStatus, msgID string) []byte {
	return []byte(string(status) + statusKeySep + msgID)
}

// extractMsgIDFromStatusKey extracts the messageID from a status-index key.
// Input key format: status + "|" + messageID (e.g. "PENDING|msg-123")
// The status is known (passed by the caller), so simply strip the prefix and separator.
func extractMsgIDFromStatusKey(key []byte, status BridgeMessageStatus) string {
	prefix := string(status) + statusKeySep
	if len(key) <= len(prefix) {
		return ""
	}
	return string(key[len(prefix):])
}

// removeStatusIndex deletes a messageID's index under every status.
//
// Purpose: in SaveMessage the status may change (e.g. PENDING → VERIFIED),
// so the old index is removed first and the new one written, avoiding index residue.
//
// Implementation: iterate all possible statuses and try deleting each.
// This is O(1) (5 fixed statuses), cheaper than a prefix scan.
func removeStatusIndex(sb *bolt.Bucket, msgID string) error {
	statuses := []BridgeMessageStatus{
		MessageStatusPending,
		MessageStatusVerified,
		MessageStatusExecuted,
		MessageStatusFailed,
		MessageStatusExpired,
	}
	for _, st := range statuses {
		key := statusIndexKey(st, msgID)
		// Delete on a missing key is a no-op; no need to check Has first
		if err := sb.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

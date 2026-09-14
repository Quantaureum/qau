// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/qaudb/db"
)

// shardCommitmentPrefix is the key prefix used to store shard commitments
// in the main chain's database. Keys have the format:
//
//	"shard_commitment:" + shardID(8 bytes LE) + height(8 bytes LE)
var shardCommitmentPrefix = []byte("shard_commitment:")

// ErrCommitterNotConfigured is returned when the committer is used before
// its database or slot function is configured.
var ErrCommitterNotConfigured = errors.New("main chain committer not configured: database or slot function is nil")

// MainChainCommitterImpl is a production-grade implementation of the
// MainChainCommitter interface. It persists shard commitments to the main
// chain's database (BoltDB), ensuring they survive node restarts and can be
// verified by any node with access to the same database.
//
// P0-2 (2026-07-13): Previously, only the test-only mockMainChain implemented
// MainChainCommitter. This production implementation stores commitments as
// key-value pairs in the main chain's db.Database, keyed by (shardID, height).
// GetLatestSlot delegates to an injected slot function (typically
// qpos.GetCurrentSlot).
//
// Design notes:
//   - Commitments are stored under a dedicated prefix to avoid collisions
//     with other database keys (accounts, storage, etc.).
//   - Writes are atomic at the single-key level (Put is atomic in BoltDB).
//     If atomic multi-key writes are needed in the future, use NewBatch.
//   - The slot function is injected (not a direct *QPOS reference) to keep
//     the committer testable without a full QPOS instance.
type MainChainCommitterImpl struct {
	mu             sync.RWMutex
	database       db.Database
	getCurrentSlot func() uint64
	// AUDIT (2026) R4-GOV-04: authenticator verifies that submitted
	// commitments carry a valid proposer signature before they are persisted.
	// When nil, SubmitShardCommitment fails closed (rejects all commitments)
	// to prevent unauthorized writers from persisting arbitrary state roots.
	// Production wires this via SetAuthenticator(ShardManager).
	authenticator CommitmentAuthenticator
}

// NewMainChainCommitter creates a production-grade MainChainCommitter backed
// by the given database. The getCurrentSlot function is used to report the
// current main chain slot (typically qpos.GetCurrentSlot).
//
// Both database and getCurrentSlot must be non-nil for production use. If
// either is nil, the committer will return ErrCommitterNotConfigured from
// all methods.
//
// AUDIT (2026) R4-GOV-04: The returned committer has no authenticator
// wired. Callers must invoke SetAuthenticator before SubmitShardCommitment
// can accept commitments — without one, all submissions are rejected
// (fail-closed) to prevent unauthorized persistence of arbitrary state
// roots. The production wiring is:
//
//	committer := NewMainChainCommitter(shardDB, qpos.GetCurrentSlot)
//	shardMgr  := NewShardManager(committer)
//	committer.SetAuthenticator(shardMgr) // ShardManager implements CommitmentAuthenticator
func NewMainChainCommitter(database db.Database, getCurrentSlot func() uint64) *MainChainCommitterImpl {
	return &MainChainCommitterImpl{
		database:       database,
		getCurrentSlot: getCurrentSlot,
	}
}

// SetAuthenticator wires the commitment authenticator used to verify
// submitted commitments carry a valid proposer signature.
// AUDIT (2026) R4-GOV-04: Without this call, SubmitShardCommitment
// rejects all commitments (fail-closed). The authenticator is typically
// the *ShardManager, which has access to the validator pubkey store and
// the canonical shard block for each (shardID, height).
func (c *MainChainCommitterImpl) SetAuthenticator(a CommitmentAuthenticator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticator = a
}

// SubmitShardCommitment persists a shard commitment to the main chain database.
// The commitment is keyed by (shardID, blockHeight), so submitting a new
// commitment for the same shard/height overwrites the previous one.
//
// P0-2 (2026-07-13): This is the production replacement for the test-only
// mockMainChain.SubmitShardCommitment which stored commitments in an
// in-memory slice.
//
// AUDIT (2026) R4-GOV-04 FIX: Before persisting, the commitment must
// pass authentication via the wired CommitmentAuthenticator. When no
// authenticator is configured, ALL submissions are rejected (fail-closed)
// to prevent unauthorized writers from persisting arbitrary (StateRoot,
// BlockHash) for any (shardID, height). Production wires the authenticator
// via SetAuthenticator(ShardManager).
func (c *MainChainCommitterImpl) SubmitShardCommitment(commitment *ShardCommitment) error {
	if c.database == nil || c.getCurrentSlot == nil {
		return ErrCommitterNotConfigured
	}
	if commitment == nil {
		return fmt.Errorf("commitment is nil")
	}
	c.mu.RLock()
	auth := c.authenticator
	c.mu.RUnlock()
	// AUDIT (2026) R4-GOV-04: Fail-closed when no authenticator is wired.
	// This prevents the pre-fix behavior where any caller could persist
	// arbitrary commitments that would then "verify" via byte comparison.
	if auth == nil {
		return fmt.Errorf("%w: no authenticator configured", ErrCommitmentUnauthenticated)
	}
	if err := auth.AuthenticateCommitment(commitment); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitmentUnauthenticated, err)
	}
	data, err := encodeShardCommitment(commitment)
	if err != nil {
		return fmt.Errorf("failed to encode shard commitment: %w", err)
	}
	key := shardCommitmentKey(commitment.ShardID, commitment.BlockHeight)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.database.Put(key, data); err != nil {
		return fmt.Errorf("failed to store shard commitment (shard=%d, height=%d): %w",
			commitment.ShardID, commitment.BlockHeight, err)
	}
	return nil
}

// VerifyShardCommitment reads a previously-stored commitment from the database
// and compares it against the given commitment. Returns (true, nil) if they
// match, (false, nil) if they differ or no stored commitment exists, and
// (false, err) on database errors.
//
// P0-2 (2026-07-13): This is the production replacement for the test-only
// mockMainChain.VerifyShardCommitment which compared against an in-memory
// slice.
//
// AUDIT (2026) R4-GOV-04 FIX: When an authenticator is wired, the
// candidate commitment must also pass authentication before being compared
// to stored bytes. This prevents a caller from "verifying" a forged
// commitment that happens to byte-match a stored one (it cannot, since
// storage now requires authentication, but defense-in-depth requires the
// verify path to reject unauthenticated inputs too). If no authenticator
// is wired, verification falls back to byte comparison only (read-only
// path is not fail-closed, unlike the submit path).
func (c *MainChainCommitterImpl) VerifyShardCommitment(commitment *ShardCommitment) (bool, error) {
	if c.database == nil || c.getCurrentSlot == nil {
		return false, ErrCommitterNotConfigured
	}
	if commitment == nil {
		return false, fmt.Errorf("commitment is nil")
	}
	c.mu.RLock()
	auth := c.authenticator
	c.mu.RUnlock()
	// AUDIT (2026) R4-GOV-04: If an authenticator is wired, the
	// candidate must pass authentication. A failed authentication means
	// the commitment is not authentic → not a match.
	if auth != nil {
		if err := auth.AuthenticateCommitment(commitment); err != nil {
			return false, nil
		}
	}
	key := shardCommitmentKey(commitment.ShardID, commitment.BlockHeight)
	c.mu.RLock()
	stored, err := c.database.Get(key)
	c.mu.RUnlock()
	if err != nil {
		// Key-not-found is not an error — the commitment simply hasn't been
		// stored yet. Return (false, nil) so callers can distinguish "not
		// stored" from actual database errors.
		if errors.Is(err, db.ErrKeyNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read shard commitment (shard=%d, height=%d): %w",
			commitment.ShardID, commitment.BlockHeight, err)
	}
	if len(stored) == 0 {
		// No stored commitment — verification fails (not yet committed).
		return false, nil
	}
	var storedCommitment ShardCommitment
	if err := decodeShardCommitment(stored, &storedCommitment); err != nil {
		return false, fmt.Errorf("failed to decode stored commitment: %w", err)
	}
	return shardCommitmentsEqual(commitment, &storedCommitment), nil
}

// GetLatestSlot returns the current main chain slot via the injected slot
// function. This is used by ShardManager to determine the commitment slot
// for shard blocks.
//
// P0-2 (2026-07-13): This is the production replacement for the test-only
// mockMainChain.GetLatestSlot which returned a fixed uint64.
func (c *MainChainCommitterImpl) GetLatestSlot() uint64 {
	if c.getCurrentSlot == nil {
		return 0
	}
	return c.getCurrentSlot()
}

// shardCommitmentKey builds the database key for a (shardID, height) pair.
// Format: prefix + shardID(8 bytes LE) + height(8 bytes LE)
func shardCommitmentKey(shardID, height uint64) []byte {
	key := make([]byte, 0, len(shardCommitmentPrefix)+16)
	key = append(key, shardCommitmentPrefix...)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], shardID)
	key = append(key, buf[:]...)
	binary.LittleEndian.PutUint64(buf[:], height)
	key = append(key, buf[:]...)
	return key
}

// encodeShardCommitment serializes a ShardCommitment to a deterministic
// binary representation. This is NOT consensus-critical encoding (it's only
// used for local database storage), but it is deterministic for verification.
//
// Layout:
//
//	ShardID       : 8 bytes (LE)
//	BlockHeight   : 8 bytes (LE)
//	BlockHash     : 32 bytes
//	StateRoot     : 32 bytes
//	CrossMsgRoot  : 32 bytes
//	CommittedSlot : 8 bytes (LE)
//	Signer        : 20 bytes        (AUDIT (2026) R4-GOV-04)
//	SigLen        : 4 bytes (LE)
//	Signature     : SigLen bytes
//
// AUDIT (2026) R4-GOV-04: Signer field added to bind each stored
// commitment to the proposer that authorized it. Legacy entries without
// the Signer field are rejected by decodeShardCommitment (length check)
// so old pre-fix data cannot be confused with authenticated commitments.
func encodeShardCommitment(c *ShardCommitment) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil commitment")
	}
	sigLen := len(c.Signature)
	buf := make([]byte, 0, 8+8+32+32+32+8+20+4+sigLen)
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], c.ShardID)
	buf = append(buf, le[:]...)
	binary.LittleEndian.PutUint64(le[:], c.BlockHeight)
	buf = append(buf, le[:]...)
	buf = append(buf, c.BlockHash[:]...)
	buf = append(buf, c.StateRoot[:]...)
	buf = append(buf, c.CrossMsgRoot[:]...)
	binary.LittleEndian.PutUint64(le[:], c.CommittedSlot)
	buf = append(buf, le[:]...)
	// AUDIT (2026) R4-GOV-04: Signer (20 bytes) — fixed width because
	// types.Address is a [20]byte value type.
	buf = append(buf, c.Signer[:]...)
	var sigLenBytes [4]byte
	binary.LittleEndian.PutUint32(sigLenBytes[:], uint32(sigLen))
	buf = append(buf, sigLenBytes[:]...)
	buf = append(buf, c.Signature...)
	return buf, nil
}

// decodeShardCommitment deserializes a ShardCommitment from the binary
// representation produced by encodeShardCommitment.
//
// AUDIT (2026) R4-GOV-04: Decoding requires the Signer field (20 bytes)
// to be present. Pre-fix entries (without Signer) will fail the length check
// and be rejected — old databases must be re-seeded with authenticated
// commitments after deployment.
func decodeShardCommitment(data []byte, c *ShardCommitment) error {
	const fixedHeader = 8 + 8 + 32 + 32 + 32 + 8 + 20 + 4
	if len(data) < fixedHeader {
		return fmt.Errorf("data too short: %d bytes (need at least %d)", len(data), fixedHeader)
	}
	offset := 0
	c.ShardID = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	c.BlockHeight = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	copy(c.BlockHash[:], data[offset:offset+32])
	offset += 32
	copy(c.StateRoot[:], data[offset:offset+32])
	offset += 32
	copy(c.CrossMsgRoot[:], data[offset:offset+32])
	offset += 32
	c.CommittedSlot = binary.LittleEndian.Uint64(data[offset:])
	offset += 8
	// AUDIT (2026) R4-GOV-04: Decode Signer (20 bytes).
	copy(c.Signer[:], data[offset:offset+20])
	offset += 20
	sigLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(sigLen) {
		return fmt.Errorf("signature truncated: need %d bytes, have %d", sigLen, len(data)-offset)
	}
	c.Signature = make([]byte, sigLen)
	copy(c.Signature, data[offset:offset+int(sigLen)])
	return nil
}

// shardCommitmentsEqual compares two commitments for equality. Used by
// VerifyShardCommitment to check that the stored commitment matches the
// one being verified.
//
// AUDIT (2026) R4-GOV-04: Comparison now includes the Signer field
// so commitments from different proposers for the same (shardID, height)
// are correctly distinguished.
func shardCommitmentsEqual(a, b *ShardCommitment) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.ShardID != b.ShardID || a.BlockHeight != b.BlockHeight {
		return false
	}
	if a.BlockHash != b.BlockHash || a.StateRoot != b.StateRoot || a.CrossMsgRoot != b.CrossMsgRoot {
		return false
	}
	if a.CommittedSlot != b.CommittedSlot {
		return false
	}
	// AUDIT (2026) R4-GOV-04: Signer must match.
	if a.Signer != b.Signer {
		return false
	}
	if len(a.Signature) != len(b.Signature) {
		return false
	}
	for i := range a.Signature {
		if a.Signature[i] != b.Signature[i] {
			return false
		}
	}
	return true
}

// Compile-time interface compliance check.
var _ MainChainCommitter = (*MainChainCommitterImpl)(nil)

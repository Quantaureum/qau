// Quantaureum Node source, version 1.0.0.
// Package txpool implements front-running protection using commit-reveal scheme.
// This prevents MEV (Miner Extractable Value) attacks by hiding transaction details
// until they are committed to a block.
//
// CRV2 (2026-08-26): Commitments are now ON-CHAIN micro-transactions
// (encoding.TxTypeCommit) instead of RPC registrations gated by a shared
// HMAC secret. See docs/commit-reveal-v2-design.md.
//
// Flow:
//
//	① Sender submits a TxTypeCommit tx: Data = commitHash = SHA3(recipient ‖ value ‖ salt)
//	   (standard tx: signed, nonce-consuming, pays gas — spam costs money)
//	② Once the commitment is ≥ MinRevealBlocks old, the sender submits the real
//	   TransferType tx with Data = salt.
//	③ The pool recomputes SHA3(recipient ‖ value ‖ salt) and consumes the matching
//	   commitment from the same sender. No match → ErrCommitmentRequired.
//
// Properties that replaced the old HMAC subsystem:
//   - Identity: the commit tx is signed — nobody can register commitments for
//     another address (old HMAC secret was extractable from client bundles).
//   - Anti-Spam: commit txs pay gas — flooding costs money (old: free RPC calls
//   - rate limits + replay caches + lockouts).
//   - Consistency: commitments live on chain — no per-node memory tables to
//     gossip or backfill (old: 84-byte P2P gossip + R72 restart backfill).
package txpool

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Front-running protection errors
var (
	ErrCommitNotFound     = errors.New("commit not found")
	ErrCommitExpired      = errors.New("commit has expired")
	ErrCommitAlreadyUsed  = errors.New("commit already revealed")
	ErrInvalidReveal      = errors.New("reveal does not match commit")
	ErrRevealTooEarly     = errors.New("reveal too early, wait for commit confirmation")
	ErrCommitmentRequired = errors.New("transaction requires commitment for front-running protection")
	ErrInvalidSalt        = errors.New("reveal transaction must carry a 32-byte salt in Data")
)

// CRV2SaltLen is the exact length of the salt carried in the Data field of a
// reveal transaction (a ≥threshold TransferType tx).
const CRV2SaltLen = 32

// CommitRevealConfig configures the commit-reveal scheme.
type CommitRevealConfig struct {
	// CommitTimeoutBlocks: how many blocks a commitment stays valid after
	// its registration height. CRV2 replaced wall-clock CommitTimeout with a
	// block-height window (deterministic across nodes, timestamp-manipulation
	// proof — audit P1-R2-07 rationale carried over).
	CommitTimeoutBlocks uint64

	// MinRevealBlocks: minimum number of blocks between the commitment's
	// on-chain height and the reveal. 1 block (12s) prevents reordering
	// attacks (audit P4-13 / P1-R2-07).
	MinRevealBlocks uint64

	// MaxPendingCommits: per-sender cap on live commitments.
	MaxPendingCommits int

	// MaxGlobalCommits: global cap on live commitments (memory bound).
	MaxGlobalCommits int

	// Enabled enables/disables front-running protection.
	Enabled bool

	// ThresholdValue: transfers with Value >= this require a commitment.
	ThresholdValue *big.Int
}

// DefaultCommitRevealConfig returns default configuration.
// CRV2: threshold raised 1 QAU → 10 QAU. With a 20M QAU supply, 1 QAU was
// 1/20,000,000 of supply — virtually every real transfer triggered the
// two-step flow. 10 QAU keeps protection where front-running is profitable
// and lets everyday transfers stay single-tx. Parameter is consensus-neutral
// (txpool policy) and can be revisited.
func DefaultCommitRevealConfig() *CommitRevealConfig {
	return &CommitRevealConfig{
		CommitTimeoutBlocks: 75,     // ≈15 min at 12s blocks
		MinRevealBlocks:     1,      // P1-R2-07: 1 block minimum (deterministic)
		MaxPendingCommits:   10,     // per sender
		MaxGlobalCommits:    100000, // memory bound
		Enabled:             true,
		// 10^19 = 10 QAU (QAU has 18 decimals). Explicit big.Int arithmetic
		// (RPC-P1-01) to avoid float64 precision hazards.
		ThresholdValue: new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil),
	}
}

// Commitment represents an on-chain commitment registered from a TxTypeCommit tx.
type Commitment struct {
	// CommitHash = SHA3(recipient ‖ value ‖ salt). Equals the commit tx's Data.
	CommitHash types.Hash
	// Sender is the commit tx's signer (From).
	Sender types.Address
	// CreatedAt (wall clock) — used only for stats/logging, never for
	// security decisions (audit P1-R2-07: block height is the deterministic clock).
	CreatedAt time.Time
	// BlockHeight is the expected on-chain height of the commit tx
	// (registration height + 1). Reveal requires
	// currentBlockHeight >= BlockHeight + MinRevealBlocks.
	BlockHeight uint64
	// Consumed is set when a matching reveal tx was admitted.
	Consumed bool
}

// CommitRevealManager manages the commit-reveal scheme.
type CommitRevealManager struct {
	mu sync.RWMutex

	// Live commitments indexed by commit hash.
	commits map[types.Hash]*Commitment

	// Commitments by sender for per-sender caps and lookup.
	commitsBySender map[types.Address][]*Commitment

	// SECURITY (audit P1-R2-07): single source of truth for the current block
	// height (R35-P3-05).
	currentBlockHeight uint64

	// audit-fix HIGH-1: track revealed (consumed) reveal-tx hashes so
	// SelectTransactions can verify high-value txs went through commit-reveal.
	revealedTxHashes map[types.Hash]bool
	revealOrder      []types.Hash // HIGH-EVICT: FIFO order for deterministic LRU eviction

	// Configuration
	config *CommitRevealConfig

	// audit-fix M-6: stop channel for background cleanup goroutine
	stopCleanup chan struct{}
	// audit-fix R11-2: prevent double-close panic on Stop()
	stopOnce sync.Once
}

// NewCommitRevealManager creates a new commit-reveal manager.
func NewCommitRevealManager(config *CommitRevealConfig) *CommitRevealManager {
	if config == nil {
		config = DefaultCommitRevealConfig()
	}
	m := &CommitRevealManager{
		commits:          make(map[types.Hash]*Commitment),
		commitsBySender:  make(map[types.Address][]*Commitment),
		revealedTxHashes: make(map[types.Hash]bool),
		config:           config,
		stopCleanup:      make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// Stop terminates the background cleanup goroutine.
func (m *CommitRevealManager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCleanup) })
}

// cleanupLoop periodically removes expired commitments (audit M-6).
func (m *CommitRevealManager) cleanupLoop() {
	ticker := time.NewTicker(7 * time.Minute / 2)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.CleanupExpired()
		}
	}
}

// ComputeCommitHash derives the commitment hash from the reveal content.
// commitHash = SHA3-256(recipient ‖ value(32B big-endian) ‖ salt).
// Exported so gobind/clients compute the identical value.
func ComputeCommitHash(recipient types.Address, value *big.Int, salt []byte) types.Hash {
	hasher := sha3.New256()
	hasher.Write(recipient[:])
	vb := make([]byte, 32)
	if value != nil {
		v := value.Bytes() // big-endian, minimal length
		copy(vb[32-len(v):], v)
	}
	hasher.Write(vb)
	hasher.Write(salt)
	var h types.Hash
	copy(h[:], hasher.Sum(nil))
	return h
}

// RegisterCommitment registers a commitment on behalf of a TxTypeCommit tx
// that passed standard pool validation (signed, nonce-consuming, gas-paying).
// Called by the pool at admission time on every node that admits the tx, so
// all nodes converge on the same commitment index without any dedicated gossip.
func (m *CommitRevealManager) RegisterCommitment(commitHash types.Hash, sender types.Address) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.commits[commitHash]; exists {
		// Duplicate registration (same tx re-propagated) — idempotent.
		return nil
	}

	if m.config.MaxGlobalCommits > 0 && len(m.commits) >= m.config.MaxGlobalCommits {
		return errors.New("global commit limit exceeded")
	}

	// Per-sender cap: bound each address's live commitments.
	if len(m.commitsBySender[sender]) >= m.config.MaxPendingCommits {
		m.cleanupExpiredCommitsLocked(sender)
		if len(m.commitsBySender[sender]) >= m.config.MaxPendingCommits {
			return errors.New("too many pending commits")
		}
	}

	// The commit tx lands in the next block at the earliest; stamping
	// currentBlockHeight+1 makes the ≥MinRevealBlocks delay deterministic
	// and slightly conservative (a delayed inclusion only increases the gap).
	commit := &Commitment{
		CommitHash:  commitHash,
		Sender:      sender,
		CreatedAt:   time.Now(),
		BlockHeight: m.currentBlockHeight + 1,
	}
	m.commits[commitHash] = commit
	m.commitsBySender[sender] = append(m.commitsBySender[sender], commit)

	return nil
}

// CheckReveal validates that a matching, unconsumed, unexpired commitment
// exists for a ≥threshold TransferType reveal tx. Called by the pool at
// admission. Does NOT consume the commitment and does NOT enforce the
// minimum reveal delay — a reveal submitted "too early" is admitted and
// deferred by SelectTransactions until the delay passes (same UX as the
// pre-CRV2 flow, where the reveal sat in the pool waiting).
func (m *CommitRevealManager) CheckReveal(tx *encoding.Transaction) error {
	if len(tx.Data) != CRV2SaltLen {
		return ErrInvalidSalt
	}
	if tx.To == nil {
		return ErrInvalidReveal
	}

	commitHash := ComputeCommitHash(*tx.To, tx.Value, tx.Data)

	m.mu.RLock()
	defer m.mu.RUnlock()

	commit, exists := m.commits[commitHash]
	if !exists {
		return ErrCommitmentRequired
	}
	if commit.Sender != tx.From {
		// CRITICAL: a commitment can only be consumed by its registrant.
		return ErrInvalidReveal
	}
	if commit.Consumed {
		return ErrCommitAlreadyUsed
	}
	if m.expiredLocked(commit) {
		delete(m.commits, commitHash)
		return ErrCommitExpired
	}
	return nil
}

// ConsumeReveal is called by SelectTransactions when a ≥threshold reveal tx
// reaches the front of its sender's nonce queue. It enforces the minimum
// reveal delay (deterministic, block-height based — P1-R2-07) and consumes
// the commitment (single-use). Returns false when the reveal must be
// deferred: commitment missing (zombie path), delay not yet satisfied, or
// any mismatch.
func (m *CommitRevealManager) ConsumeReveal(tx *encoding.Transaction) bool {
	if len(tx.Data) != CRV2SaltLen || tx.To == nil {
		return false
	}

	commitHash := ComputeCommitHash(*tx.To, tx.Value, tx.Data)

	m.mu.Lock()
	defer m.mu.Unlock()

	commit, exists := m.commits[commitHash]
	if !exists || commit.Consumed || commit.Sender != tx.From {
		return false
	}
	if m.expiredLocked(commit) {
		delete(m.commits, commitHash)
		return false
	}
	// Fail-closed when height unavailable (R26-052).
	if m.currentBlockHeight == 0 || commit.BlockHeight == 0 {
		return false
	}
	if m.currentBlockHeight-commit.BlockHeight < m.config.MinRevealBlocks {
		return false // too early — defer
	}

	commit.Consumed = true

	txHash := tx.Hash()
	if _, exists := m.revealedTxHashes[txHash]; !exists {
		m.revealOrder = append(m.revealOrder, txHash)
	}
	m.revealedTxHashes[txHash] = true
	m.evictRevealedLocked()
	return true
}

// HasCommitmentFor reports whether a live (unconsumed, unexpired) commitment
// exists for this reveal tx. Used to distinguish "waiting for reveal delay"
// (defer) from "never committed" (zombie → evict after timeout).
func (m *CommitRevealManager) HasCommitmentFor(tx *encoding.Transaction) bool {
	if len(tx.Data) != CRV2SaltLen || tx.To == nil {
		return false
	}
	commitHash := ComputeCommitHash(*tx.To, tx.Value, tx.Data)
	m.mu.RLock()
	defer m.mu.RUnlock()
	commit, exists := m.commits[commitHash]
	return exists && !commit.Consumed && commit.Sender == tx.From && !m.expiredLocked(commit)
}

// RequiresCommitment checks if a transaction value requires commit-reveal
// protection (audit-fix M-4: *big.Int for full 256-bit range).
func (m *CommitRevealManager) RequiresCommitment(value *big.Int) bool {
	if !m.config.Enabled {
		return false
	}
	if value == nil || m.config.ThresholdValue == nil {
		return false
	}
	return value.Cmp(m.config.ThresholdValue) >= 0
}

// IsTxRevealed reports whether a reveal tx hash was admitted through the
// commit-reveal path (HIGH-1: used by SelectTransactions).
func (m *CommitRevealManager) IsTxRevealed(txHash types.Hash) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revealedTxHashes[txHash]
}

// CleanupExpired removes expired commitments and returns the number removed.
// Also enforces the revealed-hash soft cap (HIGH-EVICT / H-13).
func (m *CommitRevealManager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for hash, commit := range m.commits {
		if m.expiredLocked(commit) {
			delete(m.commits, hash)
			count++
		}
	}

	for sender, commits := range m.commitsBySender {
		var active []*Commitment
		for _, commit := range commits {
			if !m.expiredLocked(commit) {
				active = append(active, commit)
			}
		}
		if len(active) == 0 {
			delete(m.commitsBySender, sender)
		} else {
			m.commitsBySender[sender] = active
		}
	}

	m.evictRevealedLocked()
	return count
}

// expiredLocked reports whether a commitment is past its block-height window.
// Callers must hold m.mu.
func (m *CommitRevealManager) expiredLocked(commit *Commitment) bool {
	return m.currentBlockHeight > commit.BlockHeight+m.config.CommitTimeoutBlocks
}

// maxRevealedTxHashes is the soft cap on tracked revealed-transaction hashes (H-4).
const maxRevealedTxHashes = 100000

// evictRevealedLocked prunes the oldest revealed-tx entries beyond the soft
// cap using revealOrder (deterministic FIFO — HIGH-EVICT / H-13).
// Callers must hold m.mu.
func (m *CommitRevealManager) evictRevealedLocked() {
	if len(m.revealedTxHashes) > maxRevealedTxHashes {
		evictCount := len(m.revealedTxHashes) - maxRevealedTxHashes
		for i := 0; i < evictCount && i < len(m.revealOrder); i++ {
			delete(m.revealedTxHashes, m.revealOrder[i])
		}
		if evictCount < len(m.revealOrder) {
			m.revealOrder = m.revealOrder[evictCount:]
		} else {
			m.revealOrder = m.revealOrder[:0]
		}
	}
}

// cleanupExpiredCommitsLocked cleans up expired commitments for one sender
// (callers hold m.mu).
func (m *CommitRevealManager) cleanupExpiredCommitsLocked(sender types.Address) {
	commits := m.commitsBySender[sender]
	var active []*Commitment
	for _, commit := range commits {
		if !m.expiredLocked(commit) {
			active = append(active, commit)
		} else {
			delete(m.commits, commit.CommitHash)
		}
	}
	if len(active) == 0 {
		delete(m.commitsBySender, sender)
	} else {
		m.commitsBySender[sender] = active
	}
}

// CommitRevealStats returns statistics about the commit-reveal manager.
type CommitRevealStats struct {
	TotalCommits    int
	PendingCommits  int
	ConsumedCommits int
	ExpiredCommits  int
	UniqueSenders   int
}

// GetStats returns current statistics.
func (m *CommitRevealManager) GetStats() *CommitRevealStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &CommitRevealStats{
		TotalCommits:  len(m.commits),
		UniqueSenders: len(m.commitsBySender),
	}
	for _, commit := range m.commits {
		if commit.Consumed {
			stats.ConsumedCommits++
		} else if m.expiredLocked(commit) {
			stats.ExpiredCommits++
		} else {
			stats.PendingCommits++
		}
	}
	return stats
}

// SetBlockHeight updates the manager's view of the canonical block height.
// SECURITY (audit P1-R2-07 / R35-P3-05): single source of truth,
// called by the node after each block is committed. CRV2: no backfill
// needed — commitments are stamped currentBlockHeight+1 at registration,
// which is valid even during warm-up (height 0 → stamp 1).
func (m *CommitRevealManager) SetBlockHeight(height uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentBlockHeight = height
}

// UpdateBlockHeight is retained for backward compatibility; see SetBlockHeight.
func (m *CommitRevealManager) UpdateBlockHeight(height uint64) {
	m.SetBlockHeight(height)
}

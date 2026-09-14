// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/quantaureum/qau/log"
	"golang.org/x/crypto/sha3"
)

// Security constants for broadcast protection
// #nosec audit-remediation: broadcast security limits
const (
	// MaxBroadcastFanout limits the number of peers to broadcast to
	MaxBroadcastFanout = 20 // Phase 1: 8→20 for 50-node scaling

	// MaxBroadcastMessageSize limits the size of broadcast messages (10MB)
	MaxBroadcastMessageSize = 10 * 1024 * 1024

	// MaxMessageAge is the maximum age of a message to accept
	MaxMessageAge = 5 * time.Minute

	// maxSeenEntries limits the number of dedup entries per seen map to prevent
	// unbounded memory growth. I22-003 FIX: cleanupCache() runs every 1 minute
	// and only deletes expired entries, but under high throughput the maps can
	// grow rapidly between cleanups. This limit triggers forced eviction.
	maxSeenEntries = 100000
)

// Broadcaster handles message broadcasting with deduplication
// #nosec audit-remediation: implements message ID tracking, nonce validation, timestamp validation
type Broadcaster struct { //nolint:unused
	host *Host

	// Deduplication cache (message ID tracking)
	seenBlocks sync.Map // map[string]time.Time
	seenTxs    sync.Map // map[string]time.Time
	seenVotes  sync.Map // map[string]time.Time

	// I22-003 FIX: approximate total entry count across all seen maps. Used as
	// a trigger for forced cleanup when the maps exceed maxSeenEntries. The
	// counter is periodically recounted in cleanupCache() to correct drift.
	seenCount atomic.Int64

	// Nonce tracking per sender
	lastNonces sync.Map // map[string]uint64

	// Cache expiration
	cacheExpiry time.Duration

	// audit-fix R2-10: stop channel to prevent goroutine leak in cleanupCache
	stopCh   chan struct{}
	stopOnce sync.Once // audit-fix NEW-25: prevent double-close panic
}

// NewBroadcaster creates a new broadcaster
func NewBroadcaster(host *Host) *Broadcaster {
	b := &Broadcaster{
		host:        host,
		cacheExpiry: 5 * time.Minute,
		stopCh:      make(chan struct{}), // audit-fix R2-10
	}

	// Start cache cleanup
	go b.cleanupCache()

	return b
}

// trackSeenEntry increments the approximate seen counter and triggers forced
// cleanup when the maps exceed maxSeenEntries.
// I22-003 FIX: prevents unbounded growth of seenBlocks/seenTxs/seenVotes.
func (b *Broadcaster) trackSeenEntry() {
	if b.seenCount.Add(1) > maxSeenEntries {
		go b.cleanupSeenMaps()
	}
}

// cleanupSeenMaps removes expired entries from all seen maps and enforces
// maxSeenEntries by evicting oldest entries when a map exceeds the limit.
// I22-003 FIX: called periodically (via cleanupCache) and on-demand when the
// approximate counter exceeds maxSeenEntries.
//
// CRIT-08 (R17, 2026-07-23): This function is launched as a short-lived
// goroutine via `go b.cleanupSeenMaps()` in trackSeenEntry(). A panic here
// (e.g., from a malformed map entry during Range) would crash the node.
// The recover protects both the async launch and the synchronous call from
// cleanupCache. On panic, the cleanup is abandoned for this cycle — the
// next cycle (or the next trackSeenEntry trigger) will retry.
func (b *Broadcaster) cleanupSeenMaps() {
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("broadcast cleanupSeenMaps panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	now := time.Now()
	expiry := b.cacheExpiry

	b.cleanSeenMap(&b.seenBlocks, now, expiry)
	b.cleanSeenMap(&b.seenTxs, now, expiry)
	b.cleanSeenMap(&b.seenVotes, now, expiry)

	// Recount the approximate total to correct counter drift.
	var total int64
	b.seenBlocks.Range(func(_, _ any) bool { total++; return true })
	b.seenTxs.Range(func(_, _ any) bool { total++; return true })
	b.seenVotes.Range(func(_, _ any) bool { total++; return true })
	b.seenCount.Store(total)
}

// cleanSeenMap cleans a single seen map: removes expired entries, then evicts
// oldest entries if the map still exceeds maxSeenEntries after expiry cleanup.
func (b *Broadcaster) cleanSeenMap(m *sync.Map, now time.Time, expiry time.Duration) {
	type entry struct {
		key string
		ts  time.Time
	}
	var remaining []entry

	m.Range(func(key, value any) bool {
		if t, ok := value.(time.Time); ok {
			if now.Sub(t) > expiry {
				m.Delete(key)
			} else {
				remaining = append(remaining, entry{key.(string), t})
			}
		}
		return true
	})

	// I22-003 FIX: if still over limit after expired cleanup, evict oldest.
	if int64(len(remaining)) > maxSeenEntries {
		sort.Slice(remaining, func(i, j int) bool {
			return remaining[i].ts.Before(remaining[j].ts)
		})
		evictCount := int64(len(remaining)) - maxSeenEntries
		for i := int64(0); i < evictCount; i++ {
			m.Delete(remaining[i].key)
		}
	}
}

// BroadcastBlock broadcasts a block to the network
func (b *Broadcaster) BroadcastBlock(ctx context.Context, blockData []byte) error {
	// Check if already seen
	hash := hashData(blockData)
	if _, seen := b.seenBlocks.LoadOrStore(hash, time.Now()); seen {
		return nil // Already broadcast
	}
	b.trackSeenEntry()

	return b.host.BroadcastBlock(ctx, blockData)
}

// BroadcastTransaction broadcasts a transaction to the network
func (b *Broadcaster) BroadcastTransaction(ctx context.Context, txData []byte) error {
	// Check if already seen
	hash := hashData(txData)
	if _, seen := b.seenTxs.LoadOrStore(hash, time.Now()); seen {
		logging.Global().Debug("BroadcastTransaction: tx already seen, skipping", map[string]any{"hash": fmt.Sprintf("%x", hash[:8])})
		return nil // Already broadcast
	}
	b.trackSeenEntry()

	logging.Global().Info("BroadcastTransaction: broadcasting new tx", map[string]any{"hash": fmt.Sprintf("%x", hash[:8]), "size": len(txData)})
	return b.host.BroadcastTransaction(ctx, txData)
}

// BroadcastVote broadcasts a vote to the network
func (b *Broadcaster) BroadcastVote(ctx context.Context, voteData []byte) error {
	// Check if already seen
	hash := hashData(voteData)
	if _, seen := b.seenVotes.LoadOrStore(hash, time.Now()); seen {
		return nil // Already broadcast
	}
	b.trackSeenEntry()

	return b.host.BroadcastVote(ctx, voteData)
}

// MarkBlockSeen marks a block as seen (for deduplication)
func (b *Broadcaster) MarkBlockSeen(blockData []byte) {
	hash := hashData(blockData)
	if _, loaded := b.seenBlocks.LoadOrStore(hash, time.Now()); !loaded {
		b.trackSeenEntry()
	}
}

// MarkTxSeen marks a transaction as seen
func (b *Broadcaster) MarkTxSeen(txData []byte) {
	hash := hashData(txData)
	if _, loaded := b.seenTxs.LoadOrStore(hash, time.Now()); !loaded {
		b.trackSeenEntry()
	}
}

// MarkTxSeenIfNew atomically marks a transaction as seen and returns whether it was new.
// TPS FIX: Used for incoming P2P dedup — prevents the same tx from being pushed to txCh
// multiple times when received from different peers. Without this, a tx broadcast to 5
// peers gets pushed to txCh up to 5 times (once per peer re-broadcast), flooding the
// channel and causing unique txs to be dropped.
// Uses the same seenTxs map as outgoing dedup, so a tx received via P2P won't be
// re-broadcast by this node (correct for fully-meshed networks).
func (b *Broadcaster) MarkTxSeenIfNew(txData []byte) bool {
	hash := hashData(txData)
	_, seen := b.seenTxs.LoadOrStore(hash, time.Now())
	if !seen {
		b.trackSeenEntry()
	}
	return !seen
}

// MarkVoteSeen marks a vote as seen
func (b *Broadcaster) MarkVoteSeen(voteData []byte) {
	hash := hashData(voteData)
	if _, loaded := b.seenVotes.LoadOrStore(hash, time.Now()); !loaded {
		b.trackSeenEntry()
	}
}

// IsBlockSeen checks if a block has been seen
func (b *Broadcaster) IsBlockSeen(blockData []byte) bool {
	hash := hashData(blockData)
	_, seen := b.seenBlocks.Load(hash)
	return seen
}

// IsTxSeen checks if a transaction has been seen
func (b *Broadcaster) IsTxSeen(txData []byte) bool {
	hash := hashData(txData)
	_, seen := b.seenTxs.Load(hash)
	return seen
}

// IsVoteSeen checks if a vote has been seen
func (b *Broadcaster) IsVoteSeen(voteData []byte) bool {
	hash := hashData(voteData)
	_, seen := b.seenVotes.Load(hash)
	return seen
}

// Stop stops the broadcaster's background goroutine.
// audit-fix R2-10: prevents goroutine leak when the Host is closed.
// audit-fix NEW-25: uses sync.Once to prevent panic on double-close.
func (b *Broadcaster) Stop() {
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
}

// cleanupCache periodically removes expired entries
func (b *Broadcaster) cleanupCache() {
	// CRIT-08 (R17, 2026-07-23): This is a long-running background goroutine
	// launched by NewBroadcaster. A panic inside the loop (e.g., from a
	// corrupted sync.Map entry or a bug in cleanSeenMap) would propagate up
	// and crash the entire node. The recover converts the panic into a log
	// entry and lets the goroutine exit cleanly rather than taking down the
	// process. The broadcaster will continue operating without cache cleanup
	// (maps may grow until memory pressure triggers GC), which is strictly
	// better than a node crash.
	defer func() {
		if r := recover(); r != nil {
			logging.Global().Error("broadcast cleanupCache panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// I22-003 FIX: clean seen maps with max entry enforcement, then
			// recount the approximate total for the trigger counter.
			b.cleanupSeenMaps()

			now := time.Now()

			// audit-fix H-1: prune stale lastNonces entries using activity-based approach.
			// Build set of active senders from seen message maps, then only prune
			// nonces for senders that have no recent activity. Delete in batches
			// to avoid blocking the Range iteration.
			activeSenders := make(map[string]bool)
			expiry := b.cacheExpiry

			b.seenBlocks.Range(func(key, value any) bool {
				if t, ok := value.(time.Time); ok && now.Sub(t) <= expiry {
					activeSenders[key.(string)] = true
				}
				return true
			})
			b.seenTxs.Range(func(key, value any) bool {
				if t, ok := value.(time.Time); ok && now.Sub(t) <= expiry {
					activeSenders[key.(string)] = true
				}
				return true
			})
			b.seenVotes.Range(func(key, value any) bool {
				if t, ok := value.(time.Time); ok && now.Sub(t) <= expiry {
					activeSenders[key.(string)] = true
				}
				return true
			})

			// Collect stale nonces (not in active set) and delete them.
			// RPC-R9-M (2026-07-19) FIX: Previously the code only deleted an
			// entry when `staleCount%batchSize == 0`, which removed 1 out of
			// every 1000 stale entries (0.1%) and left 99.9% of stale nonces
			// in the map indefinitely — an unbounded memory leak that an
			// attacker could amplify by registering many one-shot sender IDs.
			// sync.Map.Range permits concurrent Delete without panicking
			// (per Go spec), so we delete every stale entry unconditionally.
			// Iteration may skip some entries when the map is mutated mid-Range,
			// but the next cleanup pass will catch them; correctness is preserved
			// because IsNonceSeen only authoritatively rejects nonces strictly
			// less than the stored value (an attacker cannot replay by relying on
			// stale retention).
			b.lastNonces.Range(func(key, _ any) bool {
				senderID := key.(string)
				if !activeSenders[senderID] {
					b.lastNonces.Delete(key)
				}
				return true
			})
		case <-b.stopCh:
			return
		}
	}
}

// hashData creates a collision-resistant hash string for deduplication.
// audit-fix M-5: replaced CRC32 with SHA3-256 truncated to 16 hex chars (64 bits)
// to prevent attackers from crafting collisions to suppress valid messages.
func hashData(data []byte) string {
	h := sha3.Sum256(data)
	return hex.EncodeToString(h[:16])
}

// HashData returns the 32-byte SHA3-256 hash of data.
// Used by CompactTxManager for compact tx propagation.
func HashData(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}

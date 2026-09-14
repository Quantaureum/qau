// Quantaureum Node source, version 1.0.0.
package p2p

// L14-032 SECURITY NOTE: Peer reputation scoring is used to identify and
// disconnect from misbehaving peers. Peers are scored based on message
// validity, response times, and protocol compliance. Peers with scores
// below a threshold are disconnected and temporarily banned. The scoring
// system is designed to be resistant to Sybil attacks by weighting
// long-term behavior over short-term interactions. Reputation scores are
// not shared between nodes to prevent reputation manipulation.

import (
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

const (
	MaxPeerScore = 100.0
	MinPeerScore = -100.0

	DefaultScore = 0.0

	ScoreBootstrapNode = 50.0

	ScoreValidBlock       = 5.0
	ScoreValidTransaction = 1.0
	ScoreValidVote        = 2.0
	ScoreValidAttestation = 3.0

	ScoreInvalidBlock       = -20.0
	ScoreInvalidTransaction = -10.0
	ScoreInvalidVote        = -15.0
	ScoreInvalidAttestation = -20.0

	ScoreProtocolViolation    = -30.0
	ScoreTimeout              = -5.0
	ScoreUnexpectedDisconnect = -10.0

	ScoreFastResponse = 2.0
	ScoreSlowResponse = -1.0
	ScoreNoResponse   = -5.0

	ScoreUptimeBonusPerHour = 0.5
	ScoreMaxUptimeBonus     = 20.0

	ScoreDecayHalfLife = 24 * time.Hour
	ScoreDecayInterval = 10 * time.Minute

	// ScoreBanThreshold is the score below which a peer is banned.
	// R23-026: This is a named, tunable constant. To override at runtime,
	// use PeerScorer.SetBanThreshold() instead of editing this value.
	ScoreBanThreshold = -50.0

	ScoreWeightResponseTime   = 0.15
	ScoreWeightMessageQuality = 0.40
	ScoreWeightUptime         = 0.15
	ScoreWeightProtocol       = 0.20
	ScoreWeightDiscovery      = 0.10
)

type PeerScoreSnapshot struct {
	PeerID         PeerID
	TotalScore     float64
	ResponseScore  float64
	QualityScore   float64
	UptimeScore    float64
	ProtocolScore  float64
	DiscoveryScore float64
	ConnectedSince time.Time
	MessageCount   uint64
	InvalidCount   uint64
	LastSeen       time.Time
}

type PeerScorer struct {
	mu           sync.RWMutex
	scores       map[PeerID]*peerScoreEntry
	banThreshold float64 // R23-026: configurable ban threshold, defaults to ScoreBanThreshold
	// RPC-R9-M (2026-07-19) FIX: background cleanup state. Previously
	// PeerScorer relied entirely on the host calling CleanupStalePeers
	// periodically; if the host didn't (or was slow), the scores map grew
	// unbounded under Sybil churn. The background goroutine provides a
	// guaranteed floor of cleanup regardless of host behavior.
	stopCh       chan struct{}
	stopOnce     sync.Once
	cleanupStart sync.Once
}

// SetBanThreshold allows runtime configuration of the peer ban threshold.
// R23-026: Allows operators to tune peer scoring sensitivity without
// recompiling. Defaults to ScoreBanThreshold (-50.0).
func (ps *PeerScorer) SetBanThreshold(threshold float64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.banThreshold = threshold
}

// GetBanThreshold returns the current ban threshold.
func (ps *PeerScorer) GetBanThreshold() float64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if ps.banThreshold == 0 {
		return ScoreBanThreshold
	}
	return ps.banThreshold
}

type peerScoreEntry struct {
	peerID PeerID

	responseScore  float64
	qualityScore   float64
	uptimeScore    float64
	protocolScore  float64
	discoveryScore float64

	connectedSince time.Time
	lastSeen       time.Time
	messageCount   uint64
	invalidCount   uint64
	responseCount  uint64
	totalLatency   time.Duration

	lastDecay time.Time
}

// MaxPeerScoreEntries bounds the size of the PeerScorer's scores map.
// RPC-R9-M (2026-07-19) FIX: Without a cap, an attacker performing a Sybil
// churn (continuously connecting with new PeerIDs) could grow the map
// without bound. The cap is set high enough to accommodate a healthy
// network's worth of observed peers (10k ≈ 10x a typical node's peer set)
// while preventing memory exhaustion.
const MaxPeerScoreEntries = 10000

func NewPeerScorer() *PeerScorer {
	ps := &PeerScorer{
		scores:       make(map[PeerID]*peerScoreEntry),
		banThreshold: ScoreBanThreshold,
		stopCh:       make(chan struct{}),
	}
	// RPC-R9-M FIX: start a background cleanup goroutine so the scores
	// map is bounded even if the host never calls CleanupStalePeers.
	// The goroutine is started lazily via sync.Once so re-calling
	// NewPeerScorer-style constructors cannot spawn duplicates.
	ps.cleanupStart.Do(func() {
		go ps.backgroundCleanup()
	})
	return ps
}

// Stop terminates the background cleanup goroutine. Safe to call multiple
// times. After Stop returns, no further cleanup goroutines will run.
func (ps *PeerScorer) Stop() {
	ps.stopOnce.Do(func() {
		close(ps.stopCh)
	})
}

// backgroundCleanup periodically evicts stale peers and applies score decay
// so the scores map remains bounded and scores stay fresh.
//
// P2P-R15-MED-1 (2026-07-22): After moving read accessors to RLock +
// computeDecayedScores (non-mutating), the background loop is now the
// primary driver of decay mutation. The ticker runs every ScoreDecayInterval
// (10 minutes) to ensure stored scores are decayed regularly, keeping them
// fresh for write operations that add deltas to the stored values.
func (ps *PeerScorer) backgroundCleanup() {
	decayTicker := time.NewTicker(ScoreDecayInterval)
	defer decayTicker.Stop()
	evictTicker := time.NewTicker(30 * time.Minute)
	defer evictTicker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in backgroundCleanup: %v", r)
		}
	}()
	for {
		select {
		case <-decayTicker.C:
			// P2P-R15-MED-1: Apply score decay to all entries. This is the
			// primary decay path now that reads no longer mutate entries.
			ps.mu.Lock()
			for _, entry := range ps.scores {
				ps.decayEntry(entry)
			}
			ps.mu.Unlock()
		case <-evictTicker.C:
			// Evict any peer unseen for >1 hour; minScoreForRetention=0
			// means low-score peers are also evicted (the host-side
			// CleanupStalePeers can apply a stricter policy if desired).
			ps.CleanupStalePeers(time.Hour, 0)
		case <-ps.stopCh:
			return
		}
	}
}

func (ps *PeerScorer) GetOrCreate(peerID PeerID) *peerScoreEntry {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		// RPC-R9-M FIX: enforce map size cap before adding a new entry.
		// If we're at capacity, opportunistically evict stale entries
		// (lastSeen older than 1 hour). If that's still not enough, we
		// refuse to create a new entry and instead return the lowest-
		// scoring existing entry as a fallback. This biases toward
		// preserving known-good peers under Sybil pressure.
		if len(ps.scores) >= MaxPeerScoreEntries {
			ps.evictStaleLocked(time.Hour)
		}
		if len(ps.scores) >= MaxPeerScoreEntries {
			// Still at capacity — return the entry of the lowest-scoring
			// peer rather than admitting a new one. We deliberately do
			// NOT overwrite the lowest-scoring peer's entry here; the
			// background cleanup goroutine and the host's
			// CleanupStalePeers call will eventually make room. This
			// keeps the GetOrCreate contract (always returns non-nil)
			// while bounding memory.
			lowestID := PeerID("")
			lowestScore := math.MaxFloat64
			for id, e := range ps.scores {
				s := ps.computeTotalScore(e)
				if s < lowestScore {
					lowestScore = s
					lowestID = id
				}
			}
			if lowestID != "" {
				return ps.scores[lowestID]
			}
			// Map is full of identical-min-score entries; fall through
			// and admit the new peer so the caller can make progress.
		}
		entry = &peerScoreEntry{
			peerID:         peerID,
			connectedSince: time.Now(),
			lastSeen:       time.Now(),
			lastDecay:      time.Now(),
		}
		ps.scores[peerID] = entry
	}
	return entry
}

// evictStaleLocked removes peers whose lastSeen is older than maxStale.
// Caller must hold ps.mu (write).
func (ps *PeerScorer) evictStaleLocked(maxStale time.Duration) {
	cutoff := time.Now().Add(-maxStale)
	for id, e := range ps.scores {
		if e.lastSeen.Before(cutoff) {
			delete(ps.scores, id)
		}
	}
}

func (ps *PeerScorer) OnConnect(peerID PeerID, isBootstrap bool) {
	entry := ps.GetOrCreate(peerID)
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry.connectedSince = time.Now()
	entry.lastSeen = time.Now()

	if isBootstrap {
		entry.qualityScore = ScoreBootstrapNode
	}
}

func (ps *PeerScorer) OnDisconnect(peerID PeerID, expected bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	if !expected {
		entry.protocolScore += ScoreUnexpectedDisconnect
	}
}

func (ps *PeerScorer) RecordResponseTime(peerID PeerID, latency time.Duration) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.responseCount++
	entry.totalLatency += latency
	entry.lastSeen = time.Now()

	if latency < 100*time.Millisecond {
		entry.responseScore += ScoreFastResponse
	} else if latency < 500*time.Millisecond {
		entry.responseScore += ScoreFastResponse * 0.5
	} else if latency < 2*time.Second {
		entry.responseScore += ScoreSlowResponse
	} else {
		entry.responseScore += ScoreNoResponse
	}
}

func (ps *PeerScorer) RecordTimeout(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.protocolScore += ScoreTimeout
}

func (ps *PeerScorer) RecordValidBlock(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreValidBlock
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordInvalidBlock(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreInvalidBlock
	entry.invalidCount++
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordValidTransaction(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreValidTransaction
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordInvalidTransaction(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreInvalidTransaction
	entry.invalidCount++
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordValidVote(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreValidVote
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordInvalidVote(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreInvalidVote
	entry.invalidCount++
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordValidAttestation(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreValidAttestation
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordInvalidAttestation(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.qualityScore += ScoreInvalidAttestation
	entry.invalidCount++
	entry.messageCount++
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordProtocolViolation(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	entry.protocolScore += ScoreProtocolViolation
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) RecordDiscoveryResponse(peerID PeerID, nodeCount int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return
	}

	if nodeCount > 0 {
		entry.discoveryScore += float64(nodeCount) * 0.5
	} else {
		entry.discoveryScore -= 1.0
	}
	entry.lastSeen = time.Now()
}

func (ps *PeerScorer) GetScore(peerID PeerID) float64 {
	// P2P-R15-MED-1 (2026-07-22): Use RLock + computeDecayedScores (non-mutating)
	// instead of Lock + decayEntry (mutating). This allows concurrent read
	// access, eliminating the hot write-lock contention that serialized all
	// read operations under high concurrency (e.g., IsBanned called per
	// incoming peer message).
	// Decay is now applied at write time (Record*/On* methods) and in the
	// background cleanup loop, keeping stored scores fresh.
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return DefaultScore
	}

	decayed := ps.computeDecayedScores(entry)
	return ps.computeTotalScoreDecayed(decayed)
}

func (ps *PeerScorer) GetSnapshot(peerID PeerID) *PeerScoreSnapshot {
	// P2P-R15-MED-1: RLock + computeDecayedScores (non-mutating) — see GetScore.
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	entry, exists := ps.scores[peerID]
	if !exists {
		return nil
	}

	decayed := ps.computeDecayedScores(entry)

	return &PeerScoreSnapshot{
		PeerID:         peerID,
		TotalScore:     ps.computeTotalScoreDecayed(decayed),
		ResponseScore:  clampScore(decayed.responseScore),
		QualityScore:   clampScore(decayed.qualityScore),
		UptimeScore:    clampScore(decayed.uptimeScore),
		ProtocolScore:  clampScore(decayed.protocolScore),
		DiscoveryScore: clampScore(decayed.discoveryScore),
		ConnectedSince: entry.connectedSince,
		MessageCount:   entry.messageCount,
		InvalidCount:   entry.invalidCount,
		LastSeen:       entry.lastSeen,
	}
}

func (ps *PeerScorer) IsBanned(peerID PeerID) bool {
	// R37-P3-20 FIX (2026-07-31): use the configurable ban threshold
	// (SetBanThreshold, R23-026) instead of the hardcoded
	// ScoreBanThreshold constant. Previously a runtime-adjusted
	// threshold was silently ignored here, so operators tuning ban
	// sensitivity saw no effect on ban decisions.
	return ps.GetScore(peerID) <= ps.GetBanThreshold()
}

func (ps *PeerScorer) GetTopPeers(n int) []PeerID {
	// P2P-R15-MED-1: RLock + computeDecayedScores (non-mutating) — see GetScore.
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	type scoredPeer struct {
		id    PeerID
		score float64
	}

	var peers []scoredPeer
	for id, entry := range ps.scores {
		decayed := ps.computeDecayedScores(entry)
		peers = append(peers, scoredPeer{id, ps.computeTotalScoreDecayed(decayed)})
	}

	// P3-3: Replace O(n²) bubble sort with O(n log n) sort.Slice.
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].score > peers[j].score
	})

	if n > len(peers) {
		n = len(peers)
	}

	result := make([]PeerID, n)
	for i := 0; i < n; i++ {
		result[i] = peers[i].id
	}
	return result
}

func (ps *PeerScorer) GetWorstPeers(n int) []PeerID {
	// P2P-R15-MED-1: RLock + computeDecayedScores (non-mutating) — see GetScore.
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	type scoredPeer struct {
		id    PeerID
		score float64
	}

	var peers []scoredPeer
	for id, entry := range ps.scores {
		decayed := ps.computeDecayedScores(entry)
		peers = append(peers, scoredPeer{id, ps.computeTotalScoreDecayed(decayed)})
	}

	// P3-3: Replace O(n²) bubble sort with O(n log n) sort.Slice.
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].score < peers[j].score
	})

	if n > len(peers) {
		n = len(peers)
	}

	result := make([]PeerID, n)
	for i := 0; i < n; i++ {
		result[i] = peers[i].id
	}
	return result
}

func (ps *PeerScorer) RemovePeer(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.scores, peerID)
}

// CleanupStalePeers removes peer entries that haven't been seen for a long time
// or have very low scores. This prevents unbounded map growth.
// Called periodically by the host to maintain bounded memory usage.
func (ps *PeerScorer) CleanupStalePeers(maxStaleDuration time.Duration, minScoreForRetention float64) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoff := time.Now().Add(-maxStaleDuration)
	removed := 0

	for peerID, entry := range ps.scores {
		// Remove if lastSeen is too old
		if entry.lastSeen.Before(cutoff) {
			delete(ps.scores, peerID)
			removed++
			continue
		}

		// Compute current total score
		totalScore := ps.computeTotalScore(entry)

		// Remove if score is below minimum threshold (likely disconnected/banned)
		if totalScore < minScoreForRetention {
			delete(ps.scores, peerID)
			removed++
		}
	}

	return removed
}

func (ps *PeerScorer) PeerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.scores)
}

func (ps *PeerScorer) computeTotalScore(entry *peerScoreEntry) float64 {
	responseScore := clampScore(entry.responseScore) * ScoreWeightResponseTime
	qualityScore := clampScore(entry.qualityScore) * ScoreWeightMessageQuality
	uptimeScore := clampScore(entry.uptimeScore) * ScoreWeightUptime
	protocolScore := clampScore(entry.protocolScore) * ScoreWeightProtocol
	discoveryScore := clampScore(entry.discoveryScore) * ScoreWeightDiscovery

	total := responseScore + qualityScore + uptimeScore + protocolScore + discoveryScore
	return clampScore(total)
}

func (ps *PeerScorer) decayEntry(entry *peerScoreEntry) {
	now := time.Now()
	elapsed := now.Sub(entry.lastDecay)
	if elapsed < ScoreDecayInterval {
		return
	}

	intervals := float64(elapsed) / float64(ScoreDecayInterval)
	decayFactor := math.Pow(0.5, intervals/float64(ScoreDecayHalfLife/ScoreDecayInterval))

	entry.responseScore *= decayFactor
	entry.qualityScore *= decayFactor
	entry.protocolScore *= decayFactor
	entry.discoveryScore *= decayFactor

	uptimeHours := now.Sub(entry.connectedSince).Hours()
	entry.uptimeScore = math.Min(uptimeHours*ScoreUptimeBonusPerHour, ScoreMaxUptimeBonus)

	entry.lastDecay = now
}

// decayedScores holds the time-decayed score components for a peer entry,
// computed WITHOUT mutating the entry. Used by read-only accessors so they
// can hold only the read lock (RLock) instead of the write lock.
//
// P2P-R15-MED-1 (2026-07-22): Previously, read accessors (GetScore,
// GetSnapshot, GetTopPeers, GetWorstPeers) called decayEntry (which mutates
// the entry), forcing them to hold the WRITE lock. Under high read
// concurrency (e.g., IsBanned is called for every incoming peer message),
// this serialized all read access. Now reads use RLock + computeDecayedScores
// (non-mutating), and decay is applied at write time and in the background
// cleanup loop.
type decayedScores struct {
	responseScore  float64
	qualityScore   float64
	uptimeScore    float64
	protocolScore  float64
	discoveryScore float64
}

// computeDecayedScores returns the decayed score components for the entry
// WITHOUT mutating it. The caller must hold at least RLock. The returned
// values reflect the decay that would be applied by decayEntry, computed
// on-the-fly from entry.lastDecay to the current time.
func (ps *PeerScorer) computeDecayedScores(entry *peerScoreEntry) decayedScores {
	now := time.Now()
	elapsed := now.Sub(entry.lastDecay)
	if elapsed < ScoreDecayInterval {
		// No decay needed — return current values.
		return decayedScores{
			responseScore:  entry.responseScore,
			qualityScore:   entry.qualityScore,
			uptimeScore:    entry.uptimeScore,
			protocolScore:  entry.protocolScore,
			discoveryScore: entry.discoveryScore,
		}
	}

	intervals := float64(elapsed) / float64(ScoreDecayInterval)
	decayFactor := math.Pow(0.5, intervals/float64(ScoreDecayHalfLife/ScoreDecayInterval))

	uptimeHours := now.Sub(entry.connectedSince).Hours()
	decayedUptime := math.Min(uptimeHours*ScoreUptimeBonusPerHour, ScoreMaxUptimeBonus)

	return decayedScores{
		responseScore:  entry.responseScore * decayFactor,
		qualityScore:   entry.qualityScore * decayFactor,
		uptimeScore:    decayedUptime,
		protocolScore:  entry.protocolScore * decayFactor,
		discoveryScore: entry.discoveryScore * decayFactor,
	}
}

// computeTotalScoreDecayed computes the total score from decayed components
// (non-mutating). Mirrors computeTotalScore but uses pre-decayed values.
func (ps *PeerScorer) computeTotalScoreDecayed(d decayedScores) float64 {
	total := clampScore(d.responseScore)*ScoreWeightResponseTime +
		clampScore(d.qualityScore)*ScoreWeightMessageQuality +
		clampScore(d.uptimeScore)*ScoreWeightUptime +
		clampScore(d.protocolScore)*ScoreWeightProtocol +
		clampScore(d.discoveryScore)*ScoreWeightDiscovery
	return clampScore(total)
}

func clampScore(score float64) float64 {
	if score > MaxPeerScore {
		return MaxPeerScore
	}
	if score < MinPeerScore {
		return MinPeerScore
	}
	return score
}

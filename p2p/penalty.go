// Quantaureum Node source, version 1.0.0.
// Phase 1: tiered penalty mechanism — optimized for 200K nodes
// Replaces simple binary banning with a four-level graduated penalty system

package p2p

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// PenaltyLevel defines penalty levels
type PenaltyLevel int

const (
	PenaltyWarning PenaltyLevel = 0 // warning (log only, no ban)
	PenaltyTempBan PenaltyLevel = 1 // temporary ban (5 minutes)
	PenaltyLongBan PenaltyLevel = 2 // long ban (1 hour)
	PenaltyPermBan PenaltyLevel = 3 // permanent ban
)

func (l PenaltyLevel) String() string {
	switch l {
	case PenaltyWarning:
		return "warning"
	case PenaltyTempBan:
		return "temp_ban"
	case PenaltyLongBan:
		return "long_ban"
	case PenaltyPermBan:
		return "perm_ban"
	default:
		return "unknown"
	}
}

// PenaltyLevelDurations maps each level to its ban duration
var PenaltyLevelDurations = map[PenaltyLevel]time.Duration{
	PenaltyTempBan: 5 * time.Minute,
	PenaltyLongBan: 1 * time.Hour,
	PenaltyPermBan: 0, // permanent, no expiry
}

// ViolationType enumerates violation types
type ViolationType int

const (
	ViolationBadMessage     ViolationType = iota // malformed message
	ViolationRateLimit                           // rate limiting
	ViolationBadBlock                            // invalid block
	ViolationBadAttestation                      // invalid attestation
	ViolationDuplicate                           // duplicate message
	ViolationTimeout                             // timeout, no response
)

func (v ViolationType) String() string {
	switch v {
	case ViolationBadMessage:
		return "bad_message"
	case ViolationRateLimit:
		return "rate_limit"
	case ViolationBadBlock:
		return "bad_block"
	case ViolationBadAttestation:
		return "bad_attestation"
	case ViolationDuplicate:
		return "duplicate"
	case ViolationTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// ViolationWeight: weights per violation type
// Severe violations (e.g. invalid blocks) weigh more and escalate faster
// ViolationDuplicate weighs 0: duplicate messages are normal in gossip
// (the same block/vote is relayed by many nodes) and must not escalate to a ban.
var ViolationWeight = map[ViolationType]int{
	ViolationBadMessage:     1,
	ViolationRateLimit:      2,
	ViolationBadBlock:       5,
	ViolationBadAttestation: 3,
	ViolationDuplicate:      0,
	ViolationTimeout:        1,
}

// escalationThresholds: score needed to reach each level
var escalationThresholds = map[PenaltyLevel]int{
	PenaltyWarning: 0,  // start at 0
	PenaltyTempBan: 10, // 10 points → temporary ban
	PenaltyLongBan: 30, // 30 points → long ban
	PenaltyPermBan: 60, // 60 points → permanent ban
}

// penaltyEntry: a single node's penalty record
type penaltyEntry struct {
	totalScore    int
	currentLevel  PenaltyLevel
	violations    map[ViolationType]int
	lastViolation time.Time
	lastUpdate    time.Time
}

// PenaltyManager: the tiered-penalty manager
type PenaltyManager struct {
	mu        sync.RWMutex
	entries   map[PeerID]*penaltyEntry
	blacklist *Blacklist
	stopCh    chan struct{}
	doneCh    chan struct{}
	started   bool // track whether Start() was called

	// decay config: with no violations for a long time, the score gradually drops
	decayInterval time.Duration // decay check interval
	decayAmount   int           // decay amount per tick
}

// DefaultPenaltyConfig returns the default configuration
func DefaultPenaltyConfig() *PenaltyManager {
	return &PenaltyManager{
		entries:       make(map[PeerID]*penaltyEntry),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		decayInterval: 10 * time.Minute, // decay every 10 minutes
		decayAmount:   1,                // minus 1 point per tick
	}
}

// SetBlacklist sets the blacklist reference (used to enforce bans)
func (pm *PenaltyManager) SetBlacklist(bl *Blacklist) {
	pm.blacklist = bl
}

// RecordViolation records a violation and returns the new level
func (pm *PenaltyManager) RecordViolation(peerID PeerID, vType ViolationType) PenaltyLevel {
	return pm.RecordViolationWithIP(peerID, "", vType)
}

// RecordViolationWithIP is the Sybil-resistant variant of RecordViolation.
//
// P2P-C-02: when ip is non-empty, a ban triggered by escalation is written to all three layers — peer/IP/
// subnet blacklist — preventing attackers from rotating Dilithium3 keypairs to mint fresh PeerIDs
// and evade the ban. An empty ip falls back to the legacy peer-only behavior for compatibility.
//
// The ip parameter accepts "host:port" / "[v6]:port" / bare IP / bare hostname
// — the Blacklist normalizes internally.
func (pm *PenaltyManager) RecordViolationWithIP(peerID PeerID, ip string, vType ViolationType) PenaltyLevel {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry, exists := pm.entries[peerID]
	if !exists {
		entry = &penaltyEntry{
			totalScore:    0,
			currentLevel:  PenaltyWarning,
			violations:    make(map[ViolationType]int),
			lastViolation: time.Now(),
			lastUpdate:    time.Now(),
		}
		pm.entries[peerID] = entry
	}

	weight := ViolationWeight[vType]
	entry.totalScore += weight
	entry.violations[vType]++
	entry.lastViolation = time.Now()
	entry.lastUpdate = time.Now()

	// check whether to escalate
	newLevel := pm.calculateLevel(entry.totalScore)
	if newLevel > entry.currentLevel {
		entry.currentLevel = newLevel
		pm.applyBanWithIP(peerID, ip, newLevel, vType)
	}

	return entry.currentLevel
}

// calculateLevel computes the current level from the total score
func (pm *PenaltyManager) calculateLevel(score int) PenaltyLevel {
	if score >= escalationThresholds[PenaltyPermBan] {
		return PenaltyPermBan
	}
	if score >= escalationThresholds[PenaltyLongBan] {
		return PenaltyLongBan
	}
	if score >= escalationThresholds[PenaltyTempBan] {
		return PenaltyTempBan
	}
	return PenaltyWarning
}

// applyBan enforces the ban
func (pm *PenaltyManager) applyBan(peerID PeerID, level PenaltyLevel, vType ViolationType) {
	pm.applyBanWithIP(peerID, "", level, vType)
}

// applyBanWithIP is the Sybil-resistant variant of applyBan.
//
// When ip is non-empty, the ban is written to all three layers (peer/IP/subnet); an empty ip falls back
// to the legacy peer-only behavior. The IP layer is enabled at all three ban levels (TempBan/LongBan/PermBan) —
// the audit asked for "at least TempBan/LongBan to also ban the IP"; we cover all levels
// for the strongest protection.
func (pm *PenaltyManager) applyBanWithIP(peerID PeerID, ip string, level PenaltyLevel, vType ViolationType) {
	if pm.blacklist == nil {
		return
	}

	reason := fmt.Sprintf("penalty_escalation: %s violations, level=%s", vType, level)

	switch level {
	case PenaltyWarning:
		// no ban; record only
		return
	case PenaltyTempBan, PenaltyLongBan:
		duration := PenaltyLevelDurations[level]
		if ip == "" {
			pm.blacklist.AddWithDuration(peerID, reason, duration)
		} else {
			pm.blacklist.AddWithDurationWithIP(peerID, ip, reason, duration)
		}
	case PenaltyPermBan:
		if ip == "" {
			pm.blacklist.AddPermanent(peerID, reason)
		} else {
			pm.blacklist.AddPermanentWithIP(peerID, ip, reason)
		}
	}
}

// GetLevel returns a node's current penalty level
func (pm *PenaltyManager) GetLevel(peerID PeerID) PenaltyLevel {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if entry, exists := pm.entries[peerID]; exists {
		return entry.currentLevel
	}
	return PenaltyWarning
}

// GetScore returns a node's violation score
func (pm *PenaltyManager) GetScore(peerID PeerID) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if entry, exists := pm.entries[peerID]; exists {
		return entry.totalScore
	}
	return 0
}

// GetViolations returns a node's per-type violation counts
func (pm *PenaltyManager) GetViolations(peerID PeerID) map[ViolationType]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if entry, exists := pm.entries[peerID]; exists {
		result := make(map[ViolationType]int)
		for k, v := range entry.violations {
			result[k] = v
		}
		return result
	}
	return nil
}

// Reset clears a node's penalty record (for manual unbans)
func (pm *PenaltyManager) Reset(peerID PeerID) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.entries, peerID)
	if pm.blacklist != nil {
		pm.blacklist.Remove(peerID)
	}
}

// ResetAll clears all penalty records
func (pm *PenaltyManager) ResetAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.entries = make(map[PeerID]*penaltyEntry)
}

// Start launches the decay goroutine
func (pm *PenaltyManager) Start() {
	pm.mu.Lock()
	if pm.started {
		pm.mu.Unlock()
		return
	}
	pm.started = true
	pm.mu.Unlock()
	go pm.decayLoop()
}

// Stop halts the decay goroutine
func (pm *PenaltyManager) Stop() {
	pm.mu.Lock()
	if !pm.started {
		pm.mu.Unlock()
		return
	}
	// P2P-PEN-01 FIX (deep-audit 2026-07-12): clear started under the lock so a
	// second Stop() returns early instead of calling close(pm.stopCh) twice,
	// which panics with "close of closed channel".
	pm.started = false
	pm.mu.Unlock()
	close(pm.stopCh)
	<-pm.doneCh
}

// decayLoop periodically decays every node's violation score
// Nodes behaving well for long stretches see their score drop — a chance to reform
func (pm *PenaltyManager) decayLoop() {
	defer close(pm.doneCh)

	ticker := time.NewTicker(pm.decayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			// P2P-R16-L02 (2026-07-23): Recover from panics in decayAll() so
			// a single bad entry doesn't kill the loop. Without this, a panic
			// would silently stop penalty decay — well-behaved peers with
			// transient issues stay banned permanently, and the penalty map
			// grows without cleanup. The defer close(pm.doneCh) above still
			// fires when the loop exits via stopCh, so Stop() won't block.
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("penalty decayLoop panic recovered: %v", r)
					}
				}()
				pm.decayAll()
			}()
		}
	}
}

// decayAll applies one decay pass across all nodes
//
// FIX (2026-07-26): the previous decay logic diluted total violation scores,
// letting repeat offenders alternate "wait + light violation" cycles and never reach PermBan
// (the same root cause as the P2P-C-02 identity-rotation issue). Fix strategy:
//   - decay scores only for nodes at PenaltyWarning (light violations, not banned)
//   - do not decay banned nodes (TempBan/LongBan/PermBan);
//     unban is handled uniformly by the Blacklist's own expiry
//   - on repeat violations, RecordViolation accumulates again since the score was never diluted
//
// This keeps the friendly property that "light violations + long good behavior can zero out",
// while closing the "wait out the ban for score dilution → downgrade → violate again" attack path.
func (pm *PenaltyManager) decayAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	threshold := pm.decayInterval * 2 // decay only after 2+ intervals without violations
	now := time.Now()

	for peerID, entry := range pm.entries {
		// banned nodes do not decay, preventing score dilution
		if entry.currentLevel > PenaltyWarning {
			continue
		}

		// nodes with recent violations do not decay
		if now.Sub(entry.lastViolation) < threshold {
			continue
		}

		// decay the score
		entry.totalScore -= pm.decayAmount
		entry.lastUpdate = now

		// recompute the level (may de-escalate)
		newLevel := pm.calculateLevel(entry.totalScore)
		if newLevel < entry.currentLevel {
			entry.currentLevel = newLevel
			// if de-escalated to Warning, remove from the blacklist
			if newLevel == PenaltyWarning && pm.blacklist != nil {
				pm.blacklist.Remove(peerID)
			}
		}

		// when the score drops below zero, clean the record
		if entry.totalScore <= 0 {
			delete(pm.entries, peerID)
		}
	}
}

// Stats returns aggregate statistics
func (pm *PenaltyManager) Stats() map[string]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]int{
		"total_tracked": len(pm.entries),
		"warning":       0,
		"temp_ban":      0,
		"long_ban":      0,
		"perm_ban":      0,
	}

	for _, entry := range pm.entries {
		switch entry.currentLevel {
		case PenaltyWarning:
			stats["warning"]++
		case PenaltyTempBan:
			stats["temp_ban"]++
		case PenaltyLongBan:
			stats["long_ban"]++
		case PenaltyPermBan:
			stats["perm_ban"]++
		}
	}

	return stats
}

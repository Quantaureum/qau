// Quantaureum Node source, version 1.0.0.
package gossipsub

import (
	"sync"
	"time"
)

// =============================================================================
// PeerScorer — manages peer scores for GossipSub mesh maintenance
//
// Scores are used to determine which peers to keep in mesh and which to prune.
// Higher scores = better peers. Scores are based on:
//   - Message delivery reliability
//   - Response time
//   - Time in mesh (sticky score)
//   - Topic participation
// =============================================================================

const (
	// Score weights
	scoreWeightDelivery = 0.4 // Message delivery reliability
	scoreWeightLatency  = 0.2 // Response time
	scoreWeightUptime   = 0.2 // Time connected
	scoreWeightTopics   = 0.2 // Topic participation

	// Score thresholds
	scoreMinValid   = -100.0 // Below this = permanently excluded
	scoreGraylist   = -50.0  // Below this = temporarily excluded
	scoreAcceptable = 0.0    // Minimum for mesh inclusion
	scoreGood       = 50.0   // Good peer
	scoreExcellent  = 100.0  // Excellent peer

	// Decay parameters
	scoreDecayInterval = 5 * time.Minute
	scoreDecayRate     = 0.95 // Multiply score by this each decay interval
	// P2P-R14-CRIT-001 (2026-07-21): penalty decay rate, applied each
	// scoreDecayInterval. A peer that stops sending invalid/duplicate
	// messages sees its penalty decay toward 0, allowing rehabilitation
	// after a proportionate backoff window. Without this, the EMA in
	// GetScore blended freshScore (which included the FULL un-decayed
	// penalty) into the stored score, so a graylisted peer could never
	// recover — malicious peers had no incentive to improve behavior
	// and could game the system by waiting for the EMA to slowly pull
	// the stored score up (which happened too slowly for honest
	// rehabilitation but too fast for severe offenders if the EMA
	// weight was misconfigured). With explicit penalty decay, the
	// rehabilitation time scales with the severity of the offense:
	//   - 3 invalid msgs (penalty=-90): ~92 min to reach scoreAcceptable
	//   - 10 invalid msgs (penalty=-300): ~3.4 hours
	//   - 100 invalid msgs (penalty=-1000): ~5.5 hours
	penaltyDecayRate = 0.95

	// Delivery tracking
	deliveryWindow     = 5 * time.Minute
	deliveryMinSamples = 10 // Minimum samples before scoring delivery

	// AUDIT (2026) R4-P2P-03: Negative-score signals.
	// Previously the scorer only recorded positive events (message delivery,
	// mesh join, latency). There was no way to penalize a peer for sending
	// invalid messages or spamming duplicates, so a malicious peer could
	// flood the mesh with junk and still keep a positive score, staying in
	// the mesh and continuing to waste bandwidth.
	//
	// Penalty per invalid message: a new peer's neutral positive components
	// (delivery=50*0.4 + latency=50*0.2 + uptime≈0*0.2 + topics=25*0.2 ≈ +35)
	// offset the penalty. We want 3 invalid messages from a fresh peer to
	// push the score below scoreGraylist (-50): 3*30 = -90, 35-90 = -55 < -50.
	// One invalid message (penalty -30) leaves the score at +5, still above
	// scoreAcceptable (0) — a first offense doesn't ban the peer. The EMA in
	// GetScore gradually decays the penalty, allowing rehabilitation.
	invalidMessagePenalty = 30.0

	// Penalty per duplicate: deliberately small. Honest peers legitimately
	// forward duplicates when the network hasn't yet propagated our dedup
	// cache update. A small per-duplicate penalty is negligible for honest
	// peers but accumulates for a spammer sending thousands of duplicates,
	// eventually pushing them below scoreGraylist.
	duplicateMessagePenalty = 1.0

	// minPenalty clamps the accumulated penalty so a single peer cannot
	// underflow the score into a region where arithmetic precision becomes
	// a problem. -1000 is well below scoreMinValid (-100), so the clamp
	// never weakens the actual exclusion behavior.
	minPenalty = -1000.0

	// P2P-H04 FIX (R29, 2026-07-26): Mesh message-delivery deficit penalty.
	// Applied once per heartbeat window when a peer's missingForward ratio
	// (missingForwards / totalDeliveries) exceeds missingForwardRatioThreshold.
	// The penalty is sized so that 2 consecutive silent windows push a fresh
	// peer below scoreGraylist (-50): neutral positive ≈ +35, 2*-45 = -90,
	// 35-90 = -55 < -50. A single silent window (penalty -45) leaves the
	// score at -10 — still above scoreGraylist but a strong signal that
	// mesh maintenance should consider pruning. The penalty decays via
	// penaltyDecayRate so a peer that resumes forwarding can rehabilitate.
	missingForwardPenalty = 45.0

	// missingForwardRatioThreshold is the minimum missing-forward ratio
	// (missingForwards / totalDeliveries) that triggers a penalty. A peer
	// is penalized only if it missed at least this fraction of the
	// window's deliveries AND the absolute count is at least
	// missingForwardMinAbsolute (to avoid penalizing on tiny samples).
	//
	// R32-P2-07 FIX (2026-07-28): Lowered from 0.8 to 0.6. The previous
	// 0.8 threshold allowed a malicious peer to selectively censor up to
	// 79% of messages without any scoring consequence — a highly
	// effective attack for blocking specific transactions or votes while
	// avoiding graylisting. 0.6 still sits well above the noise floor of
	// normal propagation jitter (typically <30% on a healthy mesh with
	// D=6 peers) but catches selective censorship much earlier. Combined
	// with the lower missingForwardMinAbsolute (3 vs 5), this detects
	// censorship in smaller windows and quieter topics.
	missingForwardRatioThreshold = 0.6

	// missingForwardMinAbsolute is the minimum absolute missing-forward
	// count required to apply the penalty. This avoids penalizing peers
	// in quiet topics where totalDeliveries is small (e.g., 2 messages
	// in a window, peer missed 1 → ratio 0.5 but absolute count 1 is
	// indistinguishable from propagation jitter).
	//
	// R32-P2-07 FIX (2026-07-28): Lowered from 5 to 3. The previous
	// value of 5 meant that in quiet topics with <8 messages per window
	// (common for votes/attestations outside peak consensus rounds),
	// the absolute threshold was never reached even if the peer censored
	// 100% of messages. 3 is still above the 1-2 message jitter caused
	// by propagation races but catches censorship in topics with as few
	// as 5 messages per window (3 missed / 5 total = 0.6 ratio).
	missingForwardMinAbsolute = 3
)

// ScoreParams holds tunable peer-scoring parameters. R32-P2-07 FIX
// (2026-07-28): previously these were compile-time constants with no
// way to adjust at runtime. Operators running on networks with different
// threat profiles (e.g., testnet with adversarial testing vs. mainnet
// with conservative tuning) had no way to tune scoring sensitivity
// without recompiling. This struct mirrors the SetBanThreshold pattern
// from the application-layer PeerScorer (p2p/peer_score.go).
//
// All fields use the package constants as defaults. A nil ScoreParams
// (or a field set to its zero value) falls back to the default constant,
// preserving backward compatibility.
type ScoreParams struct {
	// InvalidMessagePenalty is subtracted from the peer's penalty for
	// each message that fails validation. Default: 30.0.
	// Lowering makes the scorer more lenient; raising makes it more
	// aggressive. At 30.0, 3 invalid messages from a fresh peer
	// (positive baseline ≈ +35) push the score to -55, below
	// scoreGraylist (-50).
	InvalidMessagePenalty float64

	// DuplicateMessagePenalty is subtracted for each duplicate message.
	// Default: 1.0. Deliberately small so honest peers forwarding
	// legitimate duplicates during propagation are not harmed.
	DuplicateMessagePenalty float64

	// MissingForwardPenalty is applied once per heartbeat window when
	// a peer's missing-forward ratio exceeds the threshold. Default: 45.0.
	// 2 consecutive silent windows push a fresh peer below scoreGraylist.
	MissingForwardPenalty float64

	// MissingForwardRatioThreshold is the minimum miss ratio that
	// triggers the missing-forward penalty. Default: 0.6 (was 0.8
	// before R32-P2-07). Lowering catches selective censorship earlier
	// but may increase false positives from network jitter.
	MissingForwardRatioThreshold float64

	// MissingForwardMinAbsolute is the minimum absolute miss count
	// required to apply the penalty. Default: 3 (was 5 before
	// R32-P2-07). Lowering catches censorship in quieter topics but
	// may trigger on small-sample noise.
	MissingForwardMinAbsolute int
}

// DefaultScoreParams returns the default scoring parameters, matching
// the package constants. This is the value used when no override is
// set via SetScoreParams.
func DefaultScoreParams() ScoreParams {
	return ScoreParams{
		InvalidMessagePenalty:        invalidMessagePenalty,
		DuplicateMessagePenalty:      duplicateMessagePenalty,
		MissingForwardPenalty:        missingForwardPenalty,
		MissingForwardRatioThreshold: missingForwardRatioThreshold,
		MissingForwardMinAbsolute:    missingForwardMinAbsolute,
	}
}

// PeerScorer tracks and computes peer scores
type PeerScorer struct {
	mu sync.RWMutex

	// Peer scores
	scores map[PeerID]*peerScore

	// Last decay time
	// P2P-R14-CRIT-001 (2026-07-21): this field is DEPRECATED. Decay is
	// now tracked per-peer via peerScore.lastDecay. The shared field led
	// to a bug where only the first peer queried in each 5-minute window
	// had its score decayed; all other peers' stored scores stayed stale
	// until the next window. Kept for struct layout compatibility but
	// no longer read or written by the decay path.
	lastDecay time.Time
}

// peerScore tracks individual peer metrics
type peerScore struct {
	// Current score
	score float64

	// Message delivery tracking
	msgsSent      int
	msgsDelivered int
	lastDelivery  time.Time

	// Connection tracking
	connectedAt time.Time
	lastSeen    time.Time

	// Topic participation
	topics map[string]bool

	// Mesh membership tracking
	meshSince time.Time
	inMesh    bool

	// LOW-1 FIX: Track actual round-trip time for latency-based scoring.
	// Previously computeLatencyScore always returned a hardcoded 50 placeholder.
	// This field is updated via RecordLatency() and consumed by
	// computeLatencyScore() to produce a real latency component.
	lastRTT time.Duration

	// AUDIT (2026) R4-P2P-03: Negative-score signals.
	// invalidMessages counts messages from this peer that failed validation
	// (signature/structure/etc.). Each invalid message decrements penalty.
	// duplicateMessages counts duplicate messages from this peer. Each
	// duplicate decrements penalty by a smaller amount (honest peers
	// legitimately forward duplicates during propagation).
	// penalty is the accumulated negative score, folded into the final
	// score via GetScore.
	invalidMessages   int
	duplicateMessages int
	penalty           float64

	// P2P-H04 FIX (R29, 2026-07-26): Mesh message-delivery deficit tracking.
	// For each topic the peer is in mesh with us, we count messages that
	// OTHER mesh peers delivered to us during the heartbeat window but
	// this peer did NOT. A consistently silent mesh peer is either
	// censoring the topic or so poorly connected that it's useless as a
	// mesh peer — either way, its score must drop so mesh maintenance
	// prunes it and grafts a better peer.
	//
	// missingForwards is a per-window counter reset by the heartbeat.
	// We do NOT penalize on every missing message (network jitter, peer
	// propagation delay, and our own dedup races all cause false
	// positives). Instead the heartbeat compares missingForwards against
	// the window's totalDeliveries and applies a single penalty per
	// window when the deficit ratio exceeds missingForwardRatioThreshold.
	missingForwards int

	// P2P-R14-CRIT-001 (2026-07-21): per-peer last-decay timestamp.
	// Previously PeerScorer.lastDecay was shared across all peers, so
	// only the first peer queried in each 5-minute window got its
	// score decayed. This peer also never had its penalty decayed
	// toward zero — the EMA blended freshScore (which includes the
	// full un-decayed penalty) into the stored score, so a graylisted
	// peer could not rehabilitate even after stopping bad behavior.
	// We now decay both the stored score AND the penalty per-peer.
	lastDecay time.Time
}

// NewPeerScorer creates a new peer scorer
func NewPeerScorer() *PeerScorer {
	return &PeerScorer{
		scores:    make(map[PeerID]*peerScore),
		lastDecay: time.Now(),
	}
}

// RecordMessageDelivery records that a message was delivered by a peer
func (ps *PeerScorer) RecordMessageDelivery(peerID PeerID, topic string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.msgsDelivered++
	s.lastDelivery = time.Now()
	if s.topics == nil {
		s.topics = make(map[string]bool)
	}
	s.topics[topic] = true
}

// RecordMessageSent records that we sent a message to a peer
func (ps *PeerScorer) RecordMessageSent(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.msgsSent++
}

// RecordMeshJoin records that a peer joined our mesh
func (ps *PeerScorer) RecordMeshJoin(peerID PeerID, topic string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	if !s.inMesh {
		s.inMesh = true
		s.meshSince = time.Now()
	}
	if s.topics == nil {
		s.topics = make(map[string]bool)
	}
	s.topics[topic] = true
}

// RecordMeshLeave records that a peer left our mesh
func (ps *PeerScorer) RecordMeshLeave(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.inMesh = false
}

// RecordLatency records a round-trip time measurement for a peer.
// LOW-1 FIX: Provides real latency data to computeLatencyScore instead of the
// previous hardcoded 50 placeholder. Multiple samples are averaged via an
// exponential moving average to smooth transient spikes.
func (ps *PeerScorer) RecordLatency(peerID PeerID, rtt time.Duration) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	if s.lastRTT == 0 {
		s.lastRTT = rtt
	} else {
		// Exponential moving average: weight newest sample at 30%.
		s.lastRTT = time.Duration(float64(rtt)*0.3 + float64(s.lastRTT)*0.7)
	}
}

// RecordInvalidMessage records that a peer sent a message that failed
// validation (signature/structure/etc.). The message is dropped and not
// forwarded to the mesh.
//
// AUDIT (2026) R4-P2P-03: Previously the scorer had no negative signal
// for invalid messages. A peer could flood the mesh with junk and still keep
// a positive score, staying in the mesh and continuing to waste bandwidth.
// This method decrements the peer's penalty by invalidMessagePenalty (30),
// so 3 invalid messages from a fresh peer push the score below
// scoreGraylist (-50) once blended with the neutral positive components.
func (ps *PeerScorer) RecordInvalidMessage(peerID PeerID, topic string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.invalidMessages++
	s.penalty -= invalidMessagePenalty
	if s.penalty < minPenalty {
		s.penalty = minPenalty
	}
	if s.topics == nil {
		s.topics = make(map[string]bool)
	}
	s.topics[topic] = true
}

// RecordDuplicate records that a peer sent a message we have already seen
// (dedup cache hit). The message is dropped and not forwarded.
//
// AUDIT (2026) R4-P2P-03: Honest peers legitimately forward duplicates
// during propagation (the dedup cache update hasn't reached them yet), so
// the per-duplicate penalty is deliberately small (1.0). It is negligible
// for honest peers but accumulates for a spammer sending thousands of
// duplicates, eventually pushing them below scoreGraylist.
func (ps *PeerScorer) RecordDuplicate(peerID PeerID, topic string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.duplicateMessages++
	s.penalty -= duplicateMessagePenalty
	if s.penalty < minPenalty {
		s.penalty = minPenalty
	}
}

// IncrementMissingForward records that a mesh peer failed to forward a
// message that other mesh peers delivered to us during the current
// heartbeat window. The counter is per-window and per-peer; the heartbeat
// calls ApplyMissingForwardPenalty once per window to fold the deficit
// into the peer's penalty.
//
// P2P-H04 FIX (R29, 2026-07-26): Previously the scorer had no signal for
// silent mesh peers. A peer could join the mesh, never forward a single
// message, and keep a positive score — enabling topic censorship. This
// method provides the raw data; ApplyMissingForwardPenalty applies the
// actual score penalty based on the deficit ratio.
//
// This method is cheap (just a counter increment) so it can be called
// per-message-per-peer without locking concerns. The caller should hold
// no GossipSub locks when invoking this (PeerScorer has its own mutex).
func (ps *PeerScorer) IncrementMissingForward(peerID PeerID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s := ps.getOrCreate(peerID)
	s.missingForwards++
}

// ApplyMissingForwardPenalty evaluates each tracked peer's missing-forward
// deficit and applies a single penalty per heartbeat window if the deficit
// ratio exceeds the threshold. After evaluation, the per-window counters
// are reset for all peers.
//
// P2P-H04 FIX (R29, 2026-07-26). The penalty is applied AT MOST ONCE per
// peer per window (not per missing message) so the score impact is
// bounded and predictable. Peers whose missingForwards is below the
// threshold or absolute minimum are not penalized — their counters are
// simply reset.
//
// totalWindowDeliveries is the total number of distinct messages the
// GossipSub router delivered on the peer's topic during this window. It
// is passed in by the heartbeat so we can compute the ratio without
// holding the scorer lock while iterating topics.
func (ps *PeerScorer) ApplyMissingForwardPenalty(totalWindowDeliveries int) {
	if totalWindowDeliveries <= 0 {
		// No messages this window → no signal. Reset counters and return.
		ps.mu.Lock()
		defer ps.mu.Unlock()
		for _, s := range ps.scores {
			s.missingForwards = 0
		}
		return
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	for _, s := range ps.scores {
		if s.missingForwards < missingForwardMinAbsolute {
			s.missingForwards = 0
			continue
		}
		ratio := float64(s.missingForwards) / float64(totalWindowDeliveries)
		if ratio >= missingForwardRatioThreshold {
			s.penalty -= missingForwardPenalty
			if s.penalty < minPenalty {
				s.penalty = minPenalty
			}
		}
		s.missingForwards = 0
	}
}

// GetMissingForwardCount returns the current window's missing-forward
// counter for a peer. Useful for diagnostics and tests.
func (ps *PeerScorer) GetMissingForwardCount(peerID PeerID) int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0
	}
	return s.missingForwards
}

// GetScore returns the current score for a peer.
// Score components are computed on-demand, then blended with the stored score
// for smoothing. The stored score is updated when enough time has passed.
//
// AUDIT (2026) R4-P2P-03: The penalty component (accumulated from
// RecordInvalidMessage / RecordDuplicate) is folded into freshScore so it
// influences the blended stored score.
//
// P2P-R14-CRIT-001 (2026-07-21): decay is now applied PER-PEER (not via
// a shared PeerScorer.lastDecay), and the penalty itself decays toward 0
// each interval so a peer that stops misbehaving can rehabilitate after
// a proportionate backoff window. Previously the penalty never decayed
// on its own, so a graylisted peer could not recover.
func (ps *PeerScorer) GetScore(peerID PeerID) float64 {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0
	}

	now := time.Now()
	// P2P-R14-CRIT-001: apply per-peer decay (both stored score and
	// penalty) before computing freshScore, so the returned score
	// reflects the decayed state.
	ps.applyDecayLocked(s, now)

	freshScore := ps.computeFreshScore(s)

	// Blend with stored score for smoothing. For fresh peers with no
	// stored score yet, use freshScore directly so the first GetScore
	// call returns the current state rather than 0.
	if s.score == 0 {
		s.score = freshScore
	} else {
		// Single-step EMA blend. applyDecayLocked already handled
		// multi-interval catch-up; this blend keeps the stored score
		// from jumping too sharply on a single freshScore change.
		s.score = s.score*scoreDecayRate + freshScore*(1-scoreDecayRate)
	}

	return s.score
}

// GetScoreDetailed returns the score with component breakdown
func (ps *PeerScorer) GetScoreDetailed(peerID PeerID) (total, delivery, latency, uptime, topics float64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0, 0, 0, 0, 0
	}

	now := time.Now()
	// P2P-R14-CRIT-001: apply per-peer decay before computing components.
	ps.applyDecayLocked(s, now)

	delivery = ps.computeDeliveryScore(s)
	latency = ps.computeLatencyScore(s)
	uptime = ps.computeUptimeScore(s)
	topics = ps.computeTopicsScore(s)

	// AUDIT (2026) R4-P2P-03: blend freshScore (including penalty) into
	// the stored score so the returned total reflects the penalty. This
	// mirrors GetScore's blending logic. Without this, GetScoreDetailed
	// would return a stale s.score that predates any penalty.
	freshScore := delivery*scoreWeightDelivery +
		latency*scoreWeightLatency +
		uptime*scoreWeightUptime +
		topics*scoreWeightTopics +
		s.penalty
	if s.score == 0 {
		s.score = freshScore
	} else {
		s.score = s.score*scoreDecayRate + freshScore*(1-scoreDecayRate)
	}
	total = s.score

	return
}

// computeFreshScore returns the fresh (unblended) score for a peer by
// combining all positive component scores with the accumulated penalty.
// AUDIT (2026) R4-P2P-03: extracted from GetScore so GetScoreDetailed
// can share the same blending logic.
func (ps *PeerScorer) computeFreshScore(s *peerScore) float64 {
	delivery := ps.computeDeliveryScore(s)
	latency := ps.computeLatencyScore(s)
	uptime := ps.computeUptimeScore(s)
	topics := ps.computeTopicsScore(s)

	return delivery*scoreWeightDelivery +
		latency*scoreWeightLatency +
		uptime*scoreWeightUptime +
		topics*scoreWeightTopics +
		s.penalty
}

// GetPenalty returns the accumulated penalty for a peer (negative or zero).
// Useful for diagnostics. AUDIT (2026) R4-P2P-03.
func (ps *PeerScorer) GetPenalty(peerID PeerID) float64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0
	}
	return s.penalty
}

// GetInvalidMessageCount returns the count of invalid messages recorded for
// a peer. AUDIT (2026) R4-P2P-03.
func (ps *PeerScorer) GetInvalidMessageCount(peerID PeerID) int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0
	}
	return s.invalidMessages
}

// GetDuplicateMessageCount returns the count of duplicate messages recorded
// for a peer. AUDIT (2026) R4-P2P-03.
func (ps *PeerScorer) GetDuplicateMessageCount(peerID PeerID) int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	s, exists := ps.scores[peerID]
	if !exists {
		return 0
	}
	return s.duplicateMessages
}

// getOrCreate gets or creates a peer score entry (caller must hold lock)
func (ps *PeerScorer) getOrCreate(peerID PeerID) *peerScore {
	s, exists := ps.scores[peerID]
	if !exists {
		s = &peerScore{
			score:       0,
			connectedAt: time.Now(),
			lastSeen:    time.Now(),
			// P2P-R14-CRIT-001: initialize per-peer lastDecay so the
			// first decay interval starts from peer creation, not from
			// process startup.
			lastDecay: time.Now(),
		}
		ps.scores[peerID] = s
	}
	s.lastSeen = time.Now()
	return s
}

// applyDecayLocked decays the peer's stored score and accumulated penalty
// by their respective decay rates for each elapsed scoreDecayInterval.
// Multiple intervals can elapse between calls (e.g., a peer that wasn't
// queried for 15 minutes gets 3 decay steps applied).
//
// P2P-R14-CRIT-001 (2026-07-21): previously decay was a single-step EMA
// triggered by a SHARED PeerScorer.lastDecay, which meant only one peer
// per window got decayed. Now each peer tracks its own lastDecay and we
// apply N steps if N intervals have elapsed (catch-up decay). Penalty
// also decays toward 0 so a peer that stops misbehaving can rehabilitate.
//
// Caller MUST hold ps.mu.
func (ps *PeerScorer) applyDecayLocked(s *peerScore, now time.Time) {
	if s.lastDecay.IsZero() {
		s.lastDecay = now
		return
	}
	elapsed := now.Sub(s.lastDecay)
	if elapsed < scoreDecayInterval {
		return
	}
	// Number of complete decay intervals to apply.
	steps := int(elapsed / scoreDecayInterval)
	if steps <= 0 {
		return
	}
	// Apply decay step-by-step. Using a loop with a single multiplication
	// per step (rather than math.Pow) keeps the arithmetic explicit and
	// avoids float precision surprises for large step counts.
	scoreFactor := scoreDecayRate
	penaltyFactor := penaltyDecayRate
	for i := 1; i < steps; i++ {
		scoreFactor *= scoreDecayRate
		penaltyFactor *= penaltyDecayRate
	}
	// Decay stored score toward 0 (neutral). freshScore will be blended
	// in by the caller's EMA step. Decaying toward 0 first, then blending
	// with freshScore, gives the same net effect as the old EMA but
	// correctly handles multi-interval catch-up.
	s.score *= scoreFactor
	// Decay penalty toward 0 so the peer can rehabilitate.
	s.penalty *= penaltyFactor
	// Advance lastDecay by the consumed intervals (not to `now`, in case
	// a partial interval remains).
	s.lastDecay = s.lastDecay.Add(time.Duration(steps) * scoreDecayInterval)
}

// computeDeliveryScore computes delivery reliability score (-100 to 100)
func (ps *PeerScorer) computeDeliveryScore(s *peerScore) float64 {
	if s.msgsSent < deliveryMinSamples {
		return 50 // Neutral for new peers
	}

	ratio := float64(s.msgsDelivered) / float64(s.msgsSent)
	if ratio > 1.0 {
		ratio = 1.0
	}

	// Map ratio to score: 0% -> -100, 100% -> 100
	return (ratio * 200) - 100
}

// computeLatencyScore computes latency-based score (0-100)
func (ps *PeerScorer) computeLatencyScore(s *peerScore) float64 {
	// LOW-1 FIX: Use the actual round-trip time recorded via RecordLatency.
	// If no sample has been recorded yet, fall back to the neutral 50 score.
	if s.lastRTT <= 0 {
		return 50
	}

	// Map RTT to score:
	//   <= 50ms  -> 100 (excellent)
	//   500ms    -> 50  (acceptable)
	//   >= 2000ms -> 0  (poor)
	// Linear interpolation between the anchor points, clamped to [0, 100].
	const (
		excellentRTT = 50 * time.Millisecond
		poorRTT      = 2000 * time.Millisecond
	)
	switch {
	case s.lastRTT <= excellentRTT:
		return 100
	case s.lastRTT >= poorRTT:
		return 0
	default:
		// Linear decay between excellentRTT and poorRTT.
		rangeDur := float64(poorRTT - excellentRTT)
		aboveExcellent := float64(s.lastRTT - excellentRTT)
		return 100 * (1 - aboveExcellent/rangeDur)
	}
}

// computeUptimeScore computes uptime-based score (0-100)
func (ps *PeerScorer) computeUptimeScore(s *peerScore) float64 {
	if s.connectedAt.IsZero() {
		return 50
	}

	uptime := time.Since(s.connectedAt)

	// Map uptime to score: 0s -> 0, 1h -> 100
	hours := uptime.Hours()
	if hours > 1.0 {
		return 100
	}
	return hours * 100
}

// computeTopicsScore computes topic participation score (0-100)
func (ps *PeerScorer) computeTopicsScore(s *peerScore) float64 {
	if s.topics == nil || len(s.topics) == 0 {
		return 50
	}

	// More topics = higher score, up to 4 topics
	count := float64(len(s.topics))
	if count > 4 {
		count = 4
	}
	return count * 25
}

// CleanupStalePeers removes peers that haven't been seen recently
func (ps *PeerScorer) CleanupStalePeers(maxAge time.Duration) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for pid, s := range ps.scores {
		if s.lastSeen.Before(cutoff) && !s.inMesh {
			delete(ps.scores, pid)
			removed++
		}
	}
	return removed
}

// PeerCount returns the number of tracked peers
func (ps *PeerScorer) PeerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.scores)
}

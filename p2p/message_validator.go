// Quantaureum Node source, version 1.0.0.
// Package p2p implements the peer-to-peer network layer for Quantaureum.
// This file implements message validation for P2P messages.
// Requirements: 3.3, 3.4
package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Message size limits for different message types
const (
	// DefaultMaxMessageSize is the default maximum message size for non-block
	// messages (1 MB). P2P-R19-H06 (2026-07-24): previously 10MB, which let a
	// single malicious peer dump 10MB of garbage per message into the node's
	// memory before any application-level check ran. 1MB matches Ethereum's
	// devp2p default and is ample for all non-block control messages
	// (transactions <32KB, votes <64KB, status <1KB, snap range responses
	// are bounded separately). Block broadcast/response messages use
	// MaxBlockMessageSize/MaxBlockResponseSize (10MB) since a full block with
	// 1428 Dilithium3 txs is ~7.3MB.
	DefaultMaxMessageSize = 1 * 1024 * 1024

	// MaxBlockMessageSize is the maximum size for block broadcast messages (gossip).
	// Must match MaxBlockResponseSize: a full block with 1428 Dilithium3 txs is ~7.3MB.
	// 5MB caused gossip broadcast failures where nodes couldn't receive full blocks,
	// triggering state rebuilds and transaction confirmation timeouts.
	MaxBlockMessageSize = 10 * 1024 * 1024

	// MaxTransactionMessageSize is the maximum size for transaction messages (1 MB)
	MaxTransactionMessageSize = 1 * 1024 * 1024

	// MaxVoteMessageSize is the maximum size for vote messages (64 KB)
	MaxVoteMessageSize = 64 * 1024

	// MaxStatusMessageSize is the maximum size for status messages (1 KB)
	MaxStatusMessageSize = 1 * 1024

	// MaxPingPongMessageSize is the maximum size for ping/pong messages (256 bytes)
	MaxPingPongMessageSize = 256

	// MaxFindNodeMessageSize is the maximum size for findnode messages (32 bytes = enode.ID)
	MaxFindNodeMessageSize = 32

	// MaxNeighborsMessageSize is the maximum size for neighbors messages (16 KB)
	MaxNeighborsMessageSize = 16 * 1024

	// MaxNeighborsCount is the maximum number of nodes in a neighbors response
	MaxNeighborsCount = 255

	// MaxQNRMessageSize is the maximum size for QNR messages (5 KB for Dilithium3 keys)
	MaxQNRMessageSize = 8000

	// MaxSnapStateReqSize is the maximum size for snap state request messages (1 KB)
	MaxSnapStateReqSize = 1 * 1024

	// MaxSnapStateRespSize is the maximum size for snap state response messages (10 MB)
	MaxSnapStateRespSize = 10 * 1024 * 1024

	// MaxSnapRangeReqSize is the maximum size for snap range request messages (1 KB)
	MaxSnapRangeReqSize = 1 * 1024

	// MaxSnapRangeRespSize is the maximum size for snap range response messages (10 MB)
	MaxSnapRangeRespSize = 10 * 1024 * 1024

	// ETHEREUM-PARITY SYNC (2026-08-13): size bounds for the new sync
	// message types. Req messages are small fixed/bounded structures; Resp
	// messages carry bulk sync data and share the 10 MB transport ceiling.
	MaxSnapStorageReqSize   = 1 * 1024
	MaxSnapStorageRespSize  = 10 * 1024 * 1024
	MaxSnapBytecodeReqSize  = 8 * 1024
	MaxSnapBytecodeRespSize = 10 * 1024 * 1024
	MaxHeaderReqSize        = 128
	MaxHeaderRespSize       = 10 * 1024 * 1024
	MaxReceiptReqSize       = 8 * 1024
	MaxReceiptRespSize      = 10 * 1024 * 1024

	// MaxBlockRequestSize is the maximum size for block request messages (64 KB)
	MaxBlockRequestSize = 64 * 1024

	// MaxBlockResponseSize is the maximum size for block response messages (10 MB)
	// TPS FIX: 5MB→10MB. A full block with 1428 Dilithium3 txs is ~7.3MB
	// (1428 × 5.5KB per tx). 5MB caused block sync failures where nodes couldn't
	// receive blocks from peers, stuck in syncing=true, unable to produce blocks.
	MaxBlockResponseSize = 10 * 1024 * 1024

	// MaxTxRequestSize is the maximum size for transaction request messages (64 KB)
	MaxTxRequestSize = 64 * 1024

	// MaxTxResponseSize is the maximum size for transaction response messages (1 MB)
	MaxTxResponseSize = 1 * 1024 * 1024

	// MinStatusMessageSize is the minimum size for status messages
	MinStatusMessageSize = 84

	// MinBlockRequestSize is the minimum size for block request messages
	MinBlockRequestSize = 20
)

// Validation errors
var (
	ErrMessageTooLarge      = errors.New("message exceeds size limit")
	ErrMessageTooSmall      = errors.New("message below minimum size")
	ErrInvalidMessageType   = errors.New("invalid message type")
	ErrInvalidMessageFormat = errors.New("invalid message format")
	ErrNilMessage           = errors.New("nil message")
	ErrEmptyPayload         = errors.New("empty payload not allowed for this message type")
	// audit-fix P2P-AMP-RATE: rate limiting
	ErrRateLimitExceeded = errors.New("message rate limit exceeded")
	// audit-fix P2P-REPLAY-NONCE: replay protection
	ErrReplayedMessage = errors.New("replayed message detected")
	// R12-P2P-002: duplicate message detection
	ErrDuplicateMessage = errors.New("duplicate message detected")
	// P2P-R11-CRIT-002 (2026-07-20): payload signature verification failed
	ErrPayloadSignatureInvalid = errors.New("payload signature verification failed")
)

// MessageTypeValidator validates specific message types
type MessageTypeValidator interface {
	// Validate validates the message payload
	Validate(payload []byte) error
	// MaxSize returns the maximum allowed size for this message type
	MaxSize() uint64
	// MinSize returns the minimum required size for this message type
	MinSize() uint64
}

// MessageValidator validates P2P messages before processing
// Requirements: 3.3, 3.4
// audit-fix P2P-AMP-RATE: rate limiting per message type
// audit-fix P2P-REPLAY-NONCE: timestamp-based replay protection
// MEDIUM FIX: Replaced sync.Map with mutex-protected map to prevent race conditions
// in timestamp comparison and update operations
type MessageValidator struct {
	validators      map[uint8]MessageTypeValidator
	rateLimiter     *messageRateLimiter
	syncRateLimiter *messageRateLimiter // L18-043: separate, more lenient rate limit for sync messages
	// MEDIUM FIX: Use mutex-protected map instead of sync.Map for type safety
	// and to prevent race conditions in Load-Compare-Store sequences
	lastMessagesMu sync.Mutex
	lastMessages   map[string]time.Time // tracks last seen timestamp per peer
	// SECURITY FIX: maximum entries to prevent unbounded memory growth
	maxLastMessages int

	// audit-fix H-1: Track message content hashes to prevent replay attacks
	// that bypass timestamp-only checks (e.g., same message within 1 second)
	seenMessagesMu  sync.Mutex
	seenMessages    map[string]time.Time // key: hex(sha256(message)), value: time.Now()
	maxSeenMessages int                  // LRU limit to prevent unbounded growth

	// L16-009 FIX: Ensure cleanup goroutine is started at most once.
	cleanupOnce sync.Once

	// P2P-R11-CRIT-002 (2026-07-20) FIX: Optional payload-level Dilithium3
	// signature verifier for direct-P2P messages. When set, ValidateMessage
	// invokes it for MsgTypeBlock / MsgTypeVote / MsgTypeTransaction after
	// format validation passes, and rejects messages whose signature does
	// not verify. When nil, behavior is unchanged (backward compatible).
	payloadVerifierMu sync.RWMutex
	payloadVerifier   PayloadSignatureVerifier
}

// messageRateLimiter implements rate limiting per peer per message type
// SECURITY FIX: Changed from per-message-type to per-peer-per-type to prevent
// one malicious peer from affecting rate limits for all peers.
type messageRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*timeWindowLimiter // key: "peerID-msgType"
	rate     int64                         // messages per window
	window   time.Duration                 // time window
	// SECURITY (audit P3-07): Max entries to prevent memory exhaustion.
	maxEntries int
}

// timeWindowLimiter tracks message counts in a time window
type timeWindowLimiter struct {
	count     int64
	windowEnd time.Time
}

func newMessageRateLimiter(rate int64, window time.Duration) *messageRateLimiter {
	return &messageRateLimiter{
		limiters:   make(map[string]*timeWindowLimiter),
		rate:       rate,
		window:     window,
		maxEntries: 10000, // SECURITY (P3-07): cap to prevent memory exhaustion
	}
}

// CleanupExpired removes all expired entries from the rate limiter.
// SECURITY (audit P4-): This method should be called periodically
// (e.g., via a background goroutine) to clean up expired entries proactively,
// rather than only cleaning up when at capacity during allow() calls.
func (mrl *messageRateLimiter) CleanupExpired() {
	mrl.mu.Lock()
	defer mrl.mu.Unlock()
	now := time.Now()
	for k, v := range mrl.limiters {
		if v.windowEnd.Before(now) {
			delete(mrl.limiters, k)
		}
	}
}

func (mrl *messageRateLimiter) allow(peerID PeerID, msgType uint8) bool {
	mrl.mu.Lock()
	defer mrl.mu.Unlock()
	now := time.Now()
	key := fmt.Sprintf("%s-%d", peerID, msgType)
	limiter, exists := mrl.limiters[key]
	if !exists || limiter.windowEnd.Before(now) {
		// SECURITY (audit P3-07): Evict expired entries if at capacity
		if len(mrl.limiters) >= mrl.maxEntries {
			for k, v := range mrl.limiters {
				if v.windowEnd.Before(now) {
					delete(mrl.limiters, k)
				}
			}
		}
		mrl.limiters[key] = &timeWindowLimiter{
			count:     1,
			windowEnd: now.Add(mrl.window),
		}
		return true
	}
	if limiter.count >= mrl.rate {
		return false
	}
	limiter.count++
	return true
}

// StartCleanup launches a background goroutine that periodically purges expired
// rate-limiter windows and stale message-dedup (seenMessages/lastMessages)
// entries. The goroutine runs until ctx is canceled (typically the P2P Host
// context), so no explicit Stop is required.
//
// P3-10/P3-11 FIX: messageRateLimiter.CleanupExpired() was defined but never
// invoked, and the seenMessages/lastMessages dedup maps relied solely on
// capacity-based LRU eviction (only triggered once the maps hit their 100k
// cap). A periodic sweep keeps memory bounded even under low traffic where the
// cap is never reached, and bounds the worst-case dwell time of stale entries.
func (v *MessageValidator) StartCleanup(ctx context.Context) {
	if v == nil {
		return
	}
	// L16-009 FIX: Use sync.Once to ensure only one cleanup goroutine is
	// started, even if StartCleanup is called multiple times (e.g., from
	// both NewMessageValidator and the P2P Host).
	v.cleanupOnce.Do(func() {
		go v.cleanupLoop(ctx)
	})
}

func (v *MessageValidator) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in cleanupLoop: %v", r)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired rate-limiter entries and stale dedup entries.
// It is safe to call concurrently with ValidateMessage/IsDuplicate because each
// map is mutated only under its own lock.
func (v *MessageValidator) cleanupExpired() {
	if v.rateLimiter != nil {
		v.rateLimiter.CleanupExpired()
	}
	// seenMessages: dedup window is 30s (see IsDuplicate).
	seenCutoff := time.Now().Add(-30 * time.Second)
	v.seenMessagesMu.Lock()
	for k, ts := range v.seenMessages {
		if ts.Before(seenCutoff) {
			delete(v.seenMessages, k)
		}
	}
	v.seenMessagesMu.Unlock()
	// lastMessages: replay window is maxTimestampDrift(30s)+clockDriftTolerance(2s).
	lastCutoff := time.Now().Add(-32 * time.Second)
	v.lastMessagesMu.Lock()
	for k, ts := range v.lastMessages {
		if ts.Before(lastCutoff) {
			delete(v.lastMessages, k)
		}
	}
	v.lastMessagesMu.Unlock()
}

// NewMessageValidator creates a new message validator with default validators
func NewMessageValidator() *MessageValidator {
	v := &MessageValidator{
		validators:      make(map[uint8]MessageTypeValidator),
		rateLimiter:     newMessageRateLimiter(1000, time.Second), // 1000 msgs/sec per type
		syncRateLimiter: newMessageRateLimiter(5000, time.Second), // L18-043: 5000 msgs/sec for sync
		lastMessages:    make(map[string]time.Time),
		maxLastMessages: 100000, // SECURITY FIX: cap to prevent OOM from unique peer flooding
		seenMessages:    make(map[string]time.Time),
		maxSeenMessages: 100000,
	}

	// Register default validators for each message type
	v.RegisterValidator(MsgTypeBlock, &BlockMessageValidator{})
	v.RegisterValidator(MsgTypeTransaction, &TransactionMessageValidator{})
	v.RegisterValidator(MsgTypeVote, &VoteMessageValidator{})
	v.RegisterValidator(MsgTypeBlockReq, &BlockRequestValidator{})
	v.RegisterValidator(MsgTypeBlockResp, &BlockResponseValidator{})
	v.RegisterValidator(MsgTypeTxReq, &TxRequestValidator{})
	v.RegisterValidator(MsgTypeTxResp, &TxResponseValidator{})
	v.RegisterValidator(MsgTypeStatus, &StatusMessageValidator{})
	v.RegisterValidator(MsgTypePing, &PingPongValidator{})
	v.RegisterValidator(MsgTypePong, &PingPongValidator{})
	v.RegisterValidator(MsgTypeFindNode, &FindNodeValidator{})
	v.RegisterValidator(MsgTypeNeighbors, &NeighborsValidator{})
	v.RegisterValidator(MsgTypeQNR, &QNRValidator{})
	v.RegisterValidator(MsgTypeExpert, &ExpertMessageValidator{})
	v.RegisterValidator(MsgTypeSnapStateReq, &SnapStateReqValidator{})
	v.RegisterValidator(MsgTypeSnapStateResp, &SnapStateRespValidator{})
	v.RegisterValidator(MsgTypeSnapRangeReq, &SnapRangeReqValidator{})
	v.RegisterValidator(MsgTypeSnapRangeResp, &SnapRangeRespValidator{})
	// ETHEREUM-PARITY SYNC (2026-08-13): validators for the extended sync
	// protocol (snap storage/bytecode, header-first, receipts). Without
	// registration, peer readLoop rejects these frames as invalid type.
	v.RegisterValidator(MsgTypeSnapStorageReq, &SnapStorageReqValidator{})
	v.RegisterValidator(MsgTypeSnapStorageResp, &SnapStorageRespValidator{})
	v.RegisterValidator(MsgTypeSnapBytecodeReq, &SnapBytecodeReqValidator{})
	v.RegisterValidator(MsgTypeSnapBytecodeResp, &SnapBytecodeRespValidator{})
	v.RegisterValidator(MsgTypeHeaderReq, &HeaderReqValidator{})
	v.RegisterValidator(MsgTypeHeaderResp, &HeaderRespValidator{})
	v.RegisterValidator(MsgTypeReceiptReq, &ReceiptReqValidator{})
	v.RegisterValidator(MsgTypeReceiptResp, &ReceiptRespValidator{})
	v.RegisterValidator(MsgTypeAttestation, &AttestationMessageValidator{})
	v.RegisterValidator(MsgTypeAggregateAttest, &AttestationMessageValidator{})
	v.RegisterValidator(MsgTypeProposerSlashing, &AttestationMessageValidator{})
	v.RegisterValidator(MsgTypeAttesterSlashing, &AttestationMessageValidator{})
	v.RegisterValidator(MsgTypeCheckpointSig, &CheckpointSigValidator{})
	v.RegisterValidator(MsgTypeCheckpointReq, &CheckpointReqValidator{})
	// HIGH-01 (R18, 2026-07-23): QTD seal announcement validator.
	// Max size covers slot(8) + hash(32) + sigLen(4) + Dilithium3 sig(3293)
	// + sealerCount(4) + sealers(4*N, N bounded by executive chamber size ~11).
	v.RegisterValidator(MsgTypeQTDSealAnnouncement, &QTDSealAnnouncementValidator{})
	v.RegisterValidator(MsgTypeChallenge, &ChallengeValidator{})
	v.RegisterValidator(MsgTypeChallengeResponse, &ChallengeResponseValidator{})
	v.RegisterValidator(MsgTypeBatch, &BatchMessageValidator{})
	v.RegisterValidator(MsgTypeTxHashAnnounce, &TransactionMessageValidator{}) // Reuse tx validator (non-empty payload)
	v.RegisterValidator(MsgTypeTxHashRequest, &TransactionMessageValidator{})
	v.RegisterValidator(MsgTypeTxHashResponse, &BatchMessageValidator{})     // Contains sub-messages
	v.RegisterValidator(MsgTypeCompactBlock, &TransactionMessageValidator{}) // Non-empty payload
	v.RegisterValidator(MsgTypeGossipSub, &BatchMessageValidator{})
	v.RegisterValidator(MsgTypeProtocolNegotiate, &BatchMessageValidator{})
	v.RegisterValidator(MsgTypeProtocolNegotiateResp, &BatchMessageValidator{})
	// R45-VALIDATOR-FIX (2026-08-12): Register the commit-reveal gossip
	// validator. Without this, ValidateRawMessage fails every incoming
	// MsgTypeCommit frame with "invalid message type: 29" before it ever
	// reaches routeMessage / handleConsensusProtocol — breaking P2P
	// commit propagation across validators and forcing every sealer
	// other than the commit-submitter to reject the originating tx
	// with "requires commitment for front-running protection".
	v.RegisterValidator(MsgTypeCommit, &CommitMessageValidator{})

	// L16-009 FIX: Start cleanup goroutine by default to prevent unbounded
	// growth of seenMessages map. Uses context.Background() so the goroutine
	// persists for the lifetime of the validator. The P2P Host's subsequent
	// StartCleanup(h.ctx) call is a no-op due to sync.Once.
	v.StartCleanup(context.Background())

	return v
}

// RegisterValidator registers a validator for a specific message type
func (v *MessageValidator) RegisterValidator(msgType uint8, validator MessageTypeValidator) {
	v.validators[msgType] = validator
}

// SetPayloadSignatureVerifier installs a payload-level Dilithium3 signature
// verifier for direct-P2P messages (P2P-R11-CRIT-002).
// When set, ValidateMessage invokes the verifier for MsgTypeBlock /
// MsgTypeVote / MsgTypeTransaction after format validation passes,
// and rejects messages whose signature does not verify.
// Pass nil to disable (restores backward-compatible fail-open behavior).
// Safe to call concurrently with ValidateMessage.
func (v *MessageValidator) SetPayloadSignatureVerifier(verifier PayloadSignatureVerifier) {
	v.payloadVerifierMu.Lock()
	defer v.payloadVerifierMu.Unlock()
	v.payloadVerifier = verifier
}

// ValidateMessage validates a P2P message
// Requirements: 3.3, 3.4
// audit-fix P2P-AMP-RATE: rate limiting per peer per message type (security fix)
// audit-fix P2P-REPLAY-NONCE: timestamp-based replay protection with bounds checking (security fix)
func (v *MessageValidator) ValidateMessage(msg *Message) error {
	if msg == nil {
		return ErrNilMessage
	}

	// SECURITY FIX: Rate limit per peer per message type to prevent one
	// malicious peer from exhausting rate limits for all peers.
	// L18-043 FIX: Sync messages now have a separate, more lenient rate limit
	// instead of being completely exempt, preventing attackers from bypassing
	// rate limiting by disguising messages as sync traffic.
	if v.rateLimiter != nil {
		rl := v.rateLimiter
		if isSyncMessage(msg.Type) && v.syncRateLimiter != nil {
			rl = v.syncRateLimiter
		}
		if !rl.allow(msg.From, msg.Type) {
			return ErrRateLimitExceeded
		}
	}

	// SECURITY FIX: Add timestamp bounds validation to prevent replay attacks
	// via future timestamp injection. Previously, an attacker could send a message
	// with a far-future timestamp, permanently blocking legitimate messages.
	// HIGH FIX: Allow reasonable clock drift tolerance for distributed systems
	const (
		maxTimestampFuture  = 5 * time.Second  // Max future timestamp accepted
		maxTimestampDrift   = 30 * time.Second // Max past timestamp accepted
		clockDriftTolerance = 2 * time.Second  // HIGH FIX: Allowable clock skew between nodes
	)
	if msg.Timestamp.IsZero() {
		// Timestamp not set - skip replay check (may be legacy message)
	} else {
		now := time.Now()

		// Check timestamp is not too far in the future (with drift tolerance)
		if msg.Timestamp.After(now.Add(maxTimestampFuture + clockDriftTolerance)) {
			return fmt.Errorf("timestamp too far in future: %v", msg.Timestamp)
		}

		// Check timestamp is not too old (with drift tolerance)
		if msg.Timestamp.Before(now.Add(-maxTimestampDrift - clockDriftTolerance)) {
			return fmt.Errorf("timestamp too old: %v", msg.Timestamp)
		}

		// SECURITY (audit 2026-06-24, M-6): Use message content hash for replay
		// protection instead of From field, which can be spoofed.
		msgHash := sha3.Sum256(msg.Payload)
		key := fmt.Sprintf("%x-%d", msgHash[:], msg.Type)

		// MEDIUM FIX: Use mutex-protected map for atomic Load-Compare-Store
		// This prevents race conditions where two goroutines could simultaneously
		// load the same lastTime, both compare as valid, and both store,
		// allowing a replay to succeed.
		// HIGH FIX: Add clock drift tolerance for replay detection
		v.lastMessagesMu.Lock()

		// SECURITY FIX: Evict stale entries when approaching capacity to prevent
		// unbounded memory growth from many unique peers.
		if len(v.lastMessages) >= v.maxLastMessages {
			now := time.Now()
			cutoff := now.Add(-maxTimestampDrift - clockDriftTolerance)
			for k, ts := range v.lastMessages {
				if ts.Before(cutoff) {
					delete(v.lastMessages, k)
				}
			}
			// If still at capacity after eviction, remove oldest 10%
			if len(v.lastMessages) >= v.maxLastMessages {
				evictCount := v.maxLastMessages / 10
				if evictCount < 1 {
					evictCount = 1
				}
				// Collect all entries and sort by time to batch-evict the oldest ones
				type entry struct {
					key string
					t   time.Time
				}
				entries := make([]entry, 0, len(v.lastMessages))
				for k, t := range v.lastMessages {
					entries = append(entries, entry{k, t})
				}
				sort.Slice(entries, func(i, j int) bool {
					return entries[i].t.Before(entries[j].t)
				})
				for i := 0; i < evictCount && i < len(entries); i++ {
					delete(v.lastMessages, entries[i].key)
				}
			}
		}

		lastTime, exists := v.lastMessages[key]
		if exists {
			// If this message's timestamp is not strictly after the last seen timestamp,
			// it could be a replay. Allow small drift for legitimate clock differences.
			if msg.Timestamp.Before(lastTime.Add(-clockDriftTolerance)) {
				v.lastMessagesMu.Unlock()
				return ErrReplayedMessage
			}
		}
		// Only update if this is actually newer (within tolerance)
		if !exists || msg.Timestamp.After(lastTime.Add(-clockDriftTolerance)) {
			v.lastMessages[key] = msg.Timestamp
		}
		v.lastMessagesMu.Unlock()
	}

	// Get validator for this message type
	validator, exists := v.validators[msg.Type]
	if !exists {
		return fmt.Errorf("%w: %d", ErrInvalidMessageType, msg.Type)
	}

	// Check size limits
	payloadSize := uint64(len(msg.Payload))
	if payloadSize > validator.MaxSize() {
		return fmt.Errorf("%w: size %d exceeds limit %d for message type %d",
			ErrMessageTooLarge, payloadSize, validator.MaxSize(), msg.Type)
	}

	if payloadSize < validator.MinSize() {
		return fmt.Errorf("%w: size %d below minimum %d for message type %d",
			ErrMessageTooSmall, payloadSize, validator.MinSize(), msg.Type)
	}

	// R12-P2P-002 FIX: Call IsDuplicate to check content-hash based dedup.
	// Previously, IsDuplicate was defined but never called from
	// ValidateMessage, making it dead code. Now we call it after size
	// validation but before format validation (which is the most expensive).
	//
	// R48 FIX (2026-08-05): Exempt control message types from content-hash
	// dedup. Status (type=8), Ping (type=9), Pong (type=10), FindNode (15),
	// and Neighbors (16) are high-frequency control messages that
	// legitimately have identical payloads:
	//   - Status: same chain state → same Version/NetworkID/BestHeight/BestHash
	//   - Ping/Pong: same nonce within a keepalive window
	// Previously, the second receipt of an identical Status/Ping was flagged
	// as ErrDuplicateMessage and BLOCKED from reaching the application
	// handler. This caused:
	//   1. Status messages dropped → validator address→PeerID mapping not
	//      registered → TSS message routing failures
	//   2. Ping messages dropped → connection keepalive failures →
	//      peers disconnecting and reconnecting repeatedly
	//   3. The disconnect/reconnect cascade disrupted block sync and slot
	//      progression, indirectly causing double-vote errors and slot
	//      stalls.
	// Control messages are already protected by:
	//   - Per-peer per-type rate limiting (rateLimiter / syncRateLimiter)
	//   - Timestamp-based replay protection (lastMessages map)
	//   - Format validation (each type's Validate method)
	// so content-hash dedup is redundant for them.
	if !isControlMessageType(msg.Type) {
		msgHash := fmt.Sprintf("%x-%d", sha3.Sum256(msg.Payload), msg.Type)
		if v.IsDuplicate(msgHash) {
			return ErrDuplicateMessage
		}
	}

	// Validate message format
	if err := validator.Validate(msg.Payload); err != nil {
		return err
	}

	// P2P-R11-CRIT-002 (2026-07-20) FIX: Verify payload-level Dilithium3
	// signature for sensitive message types (block / vote / transaction)
	// BEFORE the message reaches application handlers. mTLS authenticates
	// the connection, but a compromised peer (or MITM after mTLS
	// termination) could inject forged payloads that propagate through
	// the network wasting bandwidth and potentially causing consensus
	// divergence before application-layer validation rejects them.
	//
	// Fail-open when no verifier is configured (backward compat).
	v.payloadVerifierMu.RLock()
	verifier := v.payloadVerifier
	v.payloadVerifierMu.RUnlock()
	if verifier == nil {
		return nil
	}
	if err := verifier.VerifyPayload(KindFromMessageType(msg.Type), msg.Payload); err != nil {
		return fmt.Errorf("%w: type=%d: %v", ErrPayloadSignatureInvalid, msg.Type, err)
	}
	return nil
}

// audit-fix H-1: IsDuplicate checks if a message with the same content hash was recently seen
// This prevents replay attacks that bypass timestamp-only checks
// (e.g., same message sent within the same second from different connections)
func (v *MessageValidator) IsDuplicate(msgHash string) bool {
	v.seenMessagesMu.Lock()
	defer v.seenMessagesMu.Unlock()

	if seenTime, ok := v.seenMessages[msgHash]; ok {
		// If message was seen within the last 30 seconds, it's a replay
		if time.Since(seenTime) < 30*time.Second {
			return true
		}
		// Expired entry, remove it
		delete(v.seenMessages, msgHash)
	}

	// Record this message
	v.seenMessages[msgHash] = time.Now()

	// LRU eviction: if we're approaching capacity, evict oldest entries until below 90%
	// SECURITY FIX (L-5): Previously only deleted 1 entry which could leave the map
	// at capacity indefinitely. Now loop until size drops below 90% of max.
	for len(v.seenMessages) >= v.maxSeenMessages && v.maxSeenMessages > 0 {
		var oldestHash string
		var oldestTime time.Time = time.Now()

		for h, ts := range v.seenMessages {
			if ts.Before(oldestTime) {
				oldestHash = h
				oldestTime = ts
			}
		}

		if oldestHash != "" {
			delete(v.seenMessages, oldestHash)
		} else {
			break
		}

		if len(v.seenMessages) < (v.maxSeenMessages*9)/10 {
			break
		}
	}

	return false
}

// ValidateRawMessage validates raw message data before decoding
// This is used for early rejection of oversized messages
// Requirements: 3.3
func (v *MessageValidator) ValidateRawMessage(data []byte) error {
	if len(data) < MsgHeaderSize {
		return ErrMalformedMessage
	}

	// Extract message type, clearing compression flag if present
	msgTypeWithFlags := data[0]
	msgType := msgTypeWithFlags &^ MsgFlagCompressed // Clear compression flag (0x80)
	length := binary.BigEndian.Uint32(data[1:5])

	// Get validator for this message type
	validator, exists := v.validators[msgType]
	if !exists {
		return fmt.Errorf("%w: %d", ErrInvalidMessageType, msgType)
	}

	// Check size limit before processing
	if uint64(length) > validator.MaxSize() {
		return fmt.Errorf("%w: declared size %d exceeds limit %d for message type %d",
			ErrMessageTooLarge, length, validator.MaxSize(), msgType)
	}

	return nil
}

// GetMaxSizeForType returns the maximum allowed size for a message type
func (v *MessageValidator) GetMaxSizeForType(msgType uint8) (uint64, error) {
	validator, exists := v.validators[msgType]
	if !exists {
		return 0, fmt.Errorf("%w: %d", ErrInvalidMessageType, msgType)
	}
	return validator.MaxSize(), nil
}

// BlockMessageValidator validates block messages
type BlockMessageValidator struct{}

func (v *BlockMessageValidator) MaxSize() uint64 { return MaxBlockMessageSize }
func (v *BlockMessageValidator) MinSize() uint64 { return 1 } // At least 1 byte

func (v *BlockMessageValidator) Validate(payload []byte) error {
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: block message exceeds max size %d, got %d",
			ErrInvalidMessageFormat, v.MaxSize(), len(payload))
	}
	// Block format validation (empty, structure) is handled by the block decoder
	return nil
}

// TransactionMessageValidator validates transaction messages
type TransactionMessageValidator struct{}

func (v *TransactionMessageValidator) MaxSize() uint64 { return MaxTransactionMessageSize }
func (v *TransactionMessageValidator) MinSize() uint64 { return 1 } // At least 1 byte

func (v *TransactionMessageValidator) Validate(payload []byte) error {
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: transaction message exceeds max size %d, got %d",
			ErrInvalidMessageFormat, v.MaxSize(), len(payload))
	}
	// Transaction format validation (empty, structure) is handled by the transaction decoder
	return nil
}

// VoteMessageValidator validates vote messages
type VoteMessageValidator struct{}

func (v *VoteMessageValidator) MaxSize() uint64 { return MaxVoteMessageSize }
func (v *VoteMessageValidator) MinSize() uint64 { return 1 } // At least 1 byte

func (v *VoteMessageValidator) Validate(payload []byte) error {
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: vote message exceeds max size %d, got %d",
			ErrInvalidMessageFormat, v.MaxSize(), len(payload))
	}
	// Vote format validation (empty, structure) is handled by the vote decoder
	return nil
}

// StatusMessageValidator validates status messages
type StatusMessageValidator struct{}

func (v *StatusMessageValidator) MaxSize() uint64 { return MaxStatusMessageSize }
func (v *StatusMessageValidator) MinSize() uint64 { return MinStatusMessageSize }

func (v *StatusMessageValidator) Validate(payload []byte) error {
	// Status message must be at least 84 bytes:
	// Version (4) + NetworkID (8) + BestHeight (8) + BestHash (32) + GenesisHash (32)
	if len(payload) < MinStatusMessageSize {
		return fmt.Errorf("%w: status message requires at least %d bytes, got %d",
			ErrInvalidMessageFormat, MinStatusMessageSize, len(payload))
	}
	return nil
}

// PingPongValidator validates ping and pong messages
type PingPongValidator struct{}

func (v *PingPongValidator) MaxSize() uint64 { return MaxPingPongMessageSize }
func (v *PingPongValidator) MinSize() uint64 { return 0 } // Can be empty

func (v *PingPongValidator) Validate(payload []byte) error {
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: ping/pong message exceeds max size %d, got %d",
			ErrInvalidMessageFormat, v.MaxSize(), len(payload))
	}
	// Nonce format validation (empty or >=8 bytes) is handled by the ping/pong decoder
	return nil
}

// FindNodeValidator validates findnode messages
type FindNodeValidator struct{}

func (v *FindNodeValidator) MaxSize() uint64 { return MaxFindNodeMessageSize }
func (v *FindNodeValidator) MinSize() uint64 { return 32 }

func (v *FindNodeValidator) Validate(payload []byte) error {
	if len(payload) != 32 {
		return fmt.Errorf("%w: findnode requires exactly 32 bytes (enode.ID), got %d",
			ErrInvalidMessageFormat, len(payload))
	}
	return nil
}

// NeighborsValidator validates neighbors messages
type NeighborsValidator struct{}

func (v *NeighborsValidator) MaxSize() uint64 { return MaxNeighborsMessageSize }
func (v *NeighborsValidator) MinSize() uint64 { return 2 }

func (v *NeighborsValidator) Validate(payload []byte) error {
	if len(payload) < 2 {
		return fmt.Errorf("%w: neighbors message too short", ErrInvalidMessageFormat)
	}
	count := binary.BigEndian.Uint16(payload[:2])
	if count > MaxNeighborsCount {
		return fmt.Errorf("%w: neighbors count %d exceeds maximum %d",
			ErrInvalidMessageFormat, count, MaxNeighborsCount)
	}
	expectedSize := 2 + int(count)*38
	if len(payload) < expectedSize {
		return fmt.Errorf("%w: neighbors declares %d nodes but payload too small",
			ErrInvalidMessageFormat, count)
	}
	return nil
}

// QNRValidator validates QNR (Quantaureum Node Record) messages
type QNRValidator struct{}

func (v *QNRValidator) MaxSize() uint64 { return MaxQNRMessageSize }
func (v *QNRValidator) MinSize() uint64 { return 100 }

func (v *QNRValidator) Validate(payload []byte) error {
	if len(payload) < 100 {
		return fmt.Errorf("%w: QNR message too short", ErrInvalidMessageFormat)
	}
	if len(payload) > MaxQNRMessageSize {
		return fmt.Errorf("%w: QNR message exceeds max size", ErrInvalidMessageFormat)
	}
	return nil
}

// BlockRequestValidator validates block request messages
type BlockRequestValidator struct{}

func (v *BlockRequestValidator) MaxSize() uint64 { return MaxBlockRequestSize }
func (v *BlockRequestValidator) MinSize() uint64 { return MinBlockRequestSize }

func (v *BlockRequestValidator) Validate(payload []byte) error {
	// Block request must be at least 20 bytes:
	// FromHeight (8) + ToHeight (8) + HashCount (4)
	if len(payload) < MinBlockRequestSize {
		return fmt.Errorf("%w: block request requires at least %d bytes, got %d",
			ErrInvalidMessageFormat, MinBlockRequestSize, len(payload))
	}

	// Validate hash count matches payload size
	hashCount := binary.BigEndian.Uint32(payload[16:20])
	expectedSize := 20 + int(hashCount)*32
	if len(payload) < expectedSize {
		return fmt.Errorf("%w: block request declares %d hashes but payload too small",
			ErrInvalidMessageFormat, hashCount)
	}

	// Sanity check on hash count (max 100 hashes per request)
	// SECURITY FIX: Reduced from 1000 to 100 to prevent DoS attacks
	if hashCount > 100 {
		return fmt.Errorf("%w: block request hash count %d exceeds maximum 100",
			ErrInvalidMessageFormat, hashCount)
	}

	return nil
}

// BlockResponseValidator validates block response messages
type BlockResponseValidator struct{}

func (v *BlockResponseValidator) MaxSize() uint64 { return MaxBlockResponseSize }
func (v *BlockResponseValidator) MinSize() uint64 { return 0 } // Can be empty (no blocks found)

func (v *BlockResponseValidator) Validate(payload []byte) error {
	// Block response can be empty if no blocks found
	return nil
}

// TxRequestValidator validates transaction request messages
type TxRequestValidator struct{}

func (v *TxRequestValidator) MaxSize() uint64 { return MaxTxRequestSize }
func (v *TxRequestValidator) MinSize() uint64 { return 4 } // At least hash count

func (v *TxRequestValidator) Validate(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("%w: tx request requires at least 4 bytes, got %d",
			ErrInvalidMessageFormat, len(payload))
	}

	// Validate hash count matches payload size
	hashCount := binary.BigEndian.Uint32(payload[0:4])
	expectedSize := 4 + int(hashCount)*32
	if len(payload) < expectedSize {
		return fmt.Errorf("%w: tx request declares %d hashes but payload too small",
			ErrInvalidMessageFormat, hashCount)
	}

	// Sanity check on hash count (max 100 hashes per request)
	// SECURITY FIX: Reduced from 1000 to 100 to prevent DoS attacks
	if hashCount > 100 {
		return fmt.Errorf("%w: tx request hash count %d exceeds maximum 100",
			ErrInvalidMessageFormat, hashCount)
	}

	return nil
}

// TxResponseValidator validates transaction response messages
type TxResponseValidator struct{}

func (v *TxResponseValidator) MaxSize() uint64 { return MaxTxResponseSize }
func (v *TxResponseValidator) MinSize() uint64 { return 0 } // Can be empty (no txs found)

func (v *TxResponseValidator) Validate(payload []byte) error {
	// Transaction response can be empty if no transactions found
	return nil
}

// ExpertMessageValidator validates expert network messages
type ExpertMessageValidator struct{}

func (v *ExpertMessageValidator) MaxSize() uint64 { return 64 * 1024 } // 64KB max
func (v *ExpertMessageValidator) MinSize() uint64 { return 1 }         // At least 1 byte

func (v *ExpertMessageValidator) Validate(payload []byte) error {
	// Expert messages are JSON encoded, basic validation only
	if len(payload) == 0 {
		return ErrEmptyPayload
	}
	return nil
}

// AttestationMessageValidator validates QPOS attestation messages
type AttestationMessageValidator struct{}

func (v *AttestationMessageValidator) MaxSize() uint64 { return 16 * 1024 } // 16KB max
func (v *AttestationMessageValidator) MinSize() uint64 { return 1 }

func (v *AttestationMessageValidator) Validate(payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyPayload
	}
	return nil
}

// CheckpointSigValidator validates checkpoint signature messages
type CheckpointSigValidator struct{}

func (v *CheckpointSigValidator) MaxSize() uint64 { return 8 * 1024 } // 8KB max
func (v *CheckpointSigValidator) MinSize() uint64 { return 64 }

func (v *CheckpointSigValidator) Validate(payload []byte) error {
	if len(payload) < 64 {
		return fmt.Errorf("%w: checkpoint sig requires at least 64 bytes", ErrInvalidMessageFormat)
	}
	return nil
}

// CheckpointReqValidator validates checkpoint request messages
type CheckpointReqValidator struct{}

func (v *CheckpointReqValidator) MaxSize() uint64 { return 1 * 1024 } // 1KB max
func (v *CheckpointReqValidator) MinSize() uint64 { return 8 }

func (v *CheckpointReqValidator) Validate(payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("%w: checkpoint req requires at least 8 bytes", ErrInvalidMessageFormat)
	}
	return nil
}

// QTDSealAnnouncementValidator validates QTD seal announcement messages.
// HIGH-01 (R18, 2026-07-23): payload format:
//
//	[0:8]    uint64 slot
//	[8:40]   types.Hash blockHash
//	[40:44]  uint32 sigLen
//	[44:44+sigLen] QTD threshold signature (Dilithium3, 3293 bytes)
//	[44+sigLen:48+sigLen] uint32 sealerCount
//	[48+sigLen:48+sigLen+4*sealerCount] uint32 sealer indices
//
// MinSize = 8 + 32 + 4 + 1 (at least 1 byte of signature) + 4 + 0 = 49.
// MaxSize = 8 + 32 + 4 + 4096 (sig headroom) + 4 + 4*64 (sealers headroom) ~= 8.4KB.
type QTDSealAnnouncementValidator struct{}

func (v *QTDSealAnnouncementValidator) MaxSize() uint64 { return 8 * 1024 } // 8KB max
func (v *QTDSealAnnouncementValidator) MinSize() uint64 { return 49 }       // slot + hash + sigLen + 1 sig + sealerCount

func (v *QTDSealAnnouncementValidator) Validate(payload []byte) error {
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: qtd seal announcement exceeds %d bytes", ErrInvalidMessageFormat, v.MaxSize())
	}
	if len(payload) < int(v.MinSize()) {
		return fmt.Errorf("%w: qtd seal announcement requires at least %d bytes", ErrInvalidMessageFormat, v.MinSize())
	}
	// Decode and sanity-check nested lengths to reject malformed messages early.
	sigLen := binary.BigEndian.Uint32(payload[40:44])
	if sigLen == 0 || sigLen > 4096 {
		return fmt.Errorf("%w: qtd seal announcement sigLen out of range: %d", ErrInvalidMessageFormat, sigLen)
	}
	sealerOffset := 44 + int(sigLen)
	if len(payload) < sealerOffset+4 {
		return fmt.Errorf("%w: qtd seal announcement truncated before sealerCount", ErrInvalidMessageFormat)
	}
	sealerCount := binary.BigEndian.Uint32(payload[sealerOffset : sealerOffset+4])
	if sealerCount > 64 {
		return fmt.Errorf("%w: qtd seal announcement sealerCount out of range: %d", ErrInvalidMessageFormat, sealerCount)
	}
	expectedLen := sealerOffset + 4 + int(sealerCount)*4
	if len(payload) != expectedLen {
		return fmt.Errorf("%w: qtd seal announcement length mismatch: have %d, want %d", ErrInvalidMessageFormat, len(payload), expectedLen)
	}
	return nil
}

// ChallengeValidator validates challenge messages
type ChallengeValidator struct{}

func (v *ChallengeValidator) MaxSize() uint64 { return 4 * 1024 } // 4KB max
func (v *ChallengeValidator) MinSize() uint64 { return 1 }

func (v *ChallengeValidator) Validate(payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyPayload
	}
	return nil
}

// ChallengeResponseValidator validates challenge response messages
type ChallengeResponseValidator struct{}

func (v *ChallengeResponseValidator) MaxSize() uint64 { return 8 * 1024 } // 8KB max
func (v *ChallengeResponseValidator) MinSize() uint64 { return 1 }

func (v *ChallengeResponseValidator) Validate(payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyPayload
	}
	return nil
}

// BatchMessageValidator validates batch messages
type BatchMessageValidator struct{}

func (v *BatchMessageValidator) MaxSize() uint64 { return 2 * 1024 * 1024 } // 2MB max
func (v *BatchMessageValidator) MinSize() uint64 { return 4 }

func (v *BatchMessageValidator) Validate(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("%w: batch message requires at least 4 bytes, got %d",
			ErrInvalidMessageFormat, len(payload))
	}
	if uint64(len(payload)) > v.MaxSize() {
		return fmt.Errorf("%w: batch message exceeds max size %d, got %d",
			ErrInvalidMessageFormat, v.MaxSize(), len(payload))
	}
	return nil
}

// CommitMessageValidator validates R45 commit-reveal gossip messages.
//
// BUG FIX (R45-VALIDATOR-FIX, 2026-08-12): The original R45 commit-reveal
// P2P gossip implementation registered MsgTypeCommit (=29) in the
// ProtocolConsensus registry's MsgTypes map and added it to
// routeMessage's default-branch dispatch path, but FORGOT to:
//  1. Register a validator for MsgTypeCommit with MessageValidator
//     (RegisterDefaultValidators below)
//  2. Add MsgTypeCommit to the ValidateMessageType whitelist
//
// Without (1), a receiving readLoop rejects all incoming MsgTypeCommit frames
// as an unregistered message type before they reach routeMessage or
// handleConsensusProtocol. Broadcast accounting can report the bytes as sent
// even though every receiver discards them, so no peer stores the commitment.
// A later block including the corresponding transaction is then rejected by
// BatchAdd's pre-lock commitment check.
//
// Wire format (see txpool.EncodeCommitMessage): exactly 84 bytes —
//
//	commitHash (32) || txHash (32) || sender (20).
//
// Validates exact length 84 since DecodeCommitMessage rejects any other
// length anyway; failing fast here avoids the wire→decode round-trip.
type CommitMessageValidator struct{}

func (v *CommitMessageValidator) MaxSize() uint64 { return 84 }
func (v *CommitMessageValidator) MinSize() uint64 { return 84 }

func (v *CommitMessageValidator) Validate(payload []byte) error {
	if len(payload) != 84 {
		return fmt.Errorf("%w: commit message must be exactly 84 bytes (32 commitHash + 32 txHash + 20 sender), got %d",
			ErrInvalidMessageFormat, len(payload))
	}
	return nil
}

// isControlMessageType returns true for high-frequency control messages that
// legitimately have identical payloads and should be exempt from content-hash
// dedup. See R48 FIX in ValidateMessage for the full rationale.
//
// MsgTypeBlockReq and MsgTypeBlockResp are included because a syncing node
// legitimately re-sends an identical block-range request (same FromHeight/
// ToHeight) while its peer is slow to respond, and the peer re-sends the same
// block batch in response. Content-hash dedup previously flagged these retries
// as replays and blocked them for 30s, causing sync stalls of up to ~60s. Both
// are already protected against abuse by per-peer sync rate limiting
// (syncRateLimiter) and timestamp-based replay protection (lastMessages map),
// so content-hash dedup is redundant for them.
func isControlMessageType(msgType uint8) bool {
	switch msgType {
	case MsgTypeStatus, MsgTypePing, MsgTypePong,
		MsgTypeFindNode, MsgTypeNeighbors,
		MsgTypeBlockReq, MsgTypeBlockResp,
		// ETHEREUM-PARITY SYNC (2026-08-13): sync request/response pairs are
		// retried with identical payloads while a peer is slow (same rationale
		// as BlockReq/BlockResp above); content-hash dedup would flag the
		// retries as replays and stall header/receipt/snap sync.
		MsgTypeHeaderReq, MsgTypeHeaderResp,
		MsgTypeReceiptReq, MsgTypeReceiptResp,
		MsgTypeSnapStorageReq, MsgTypeSnapStorageResp,
		MsgTypeSnapBytecodeReq, MsgTypeSnapBytecodeResp:
		return true
	default:
		return false
	}
}

// ValidateMessageType checks if a message type is valid
func ValidateMessageType(msgType uint8) bool {
	switch msgType {
	case MsgTypeBlock, MsgTypeTransaction, MsgTypeVote,
		MsgTypeBlockReq, MsgTypeBlockResp,
		MsgTypeTxReq, MsgTypeTxResp,
		MsgTypeStatus, MsgTypePing, MsgTypePong,
		MsgTypeFindNode, MsgTypeNeighbors, MsgTypeQNR,
		MsgTypeExpert,
		MsgTypeSnapStateReq, MsgTypeSnapStateResp,
		MsgTypeSnapRangeReq, MsgTypeSnapRangeResp,
		// ETHEREUM-PARITY SYNC (2026-08-13)
		MsgTypeSnapStorageReq, MsgTypeSnapStorageResp,
		MsgTypeSnapBytecodeReq, MsgTypeSnapBytecodeResp,
		MsgTypeHeaderReq, MsgTypeHeaderResp,
		MsgTypeReceiptReq, MsgTypeReceiptResp,
		MsgTypeAttestation, MsgTypeAggregateAttest,
		MsgTypeProposerSlashing, MsgTypeAttesterSlashing,
		MsgTypeCheckpointSig, MsgTypeCheckpointReq,
		MsgTypeChallenge, MsgTypeChallengeResponse,
		MsgTypeBatch,
		MsgTypeTxHashAnnounce, MsgTypeTxHashRequest, MsgTypeTxHashResponse,
		MsgTypeCompactBlock,
		MsgTypeProofOfWork, // L19-001 FIX: add ProofOfWork handshake message type
		// P0-10 (2026-07-14): DAS protocol message types
		MsgTypeDASSampleReq, MsgTypeDASSampleResp,
		MsgTypeDASAttestation, MsgTypeDASAggregateAttest,
		// TSS protocol message types
		MsgTypeTSSSessionInit, MsgTypeTSSRound1Commit,
		MsgTypeTSSRound2Reveal, MsgTypeTSSRound2Private,
		MsgTypeTSSSignature, MsgTypeTSSDKGShare, MsgTypeTSSKeyExchange,
		// Task 5 (node-layer distributed DKG) round messages
		MsgTypeTSSDKGCommitment, MsgTypeTSSDKGAck,
		// QTD consensus message types
		MsgTypeQTDSealRequest, MsgTypeQTDPartialSeal,
		// HIGH-01 (R18, 2026-07-23): completed QTD seal announcement
		MsgTypeQTDSealAnnouncement,
		// R45-VALIDATOR-FIX (2026-08-12): commit-reveal gossip propagated
		// from one validator's CommitRevealManager (after qau_submitCommitment
		// RPC) to all peer validators so whichever one is the next sealer
		// has the commit in its local store. Wire format: 84 bytes
		// (commitHash || txHash || sender). Mandatory here because
		// ValidateRawMessage uses the same validators map; without this
		// entry, peer readLoop rejects MsgTypeCommit frames as invalid
		// type — breaking the full R45 commit gossip pipeline.
		MsgTypeCommit,
		// Shard protocol message types (P1-1)
		MsgTypeShardBlock, MsgTypeShardBlockReq, MsgTypeShardBlockResp,
		MsgTypeShardAttestation, MsgTypeCrossShardMsg, MsgTypeCrossShardReceipt:
		return true
	default:
		return false
	}
}

// ValidateStatusMessageFormat validates the format of a status message payload
// Requirements: 3.4
func ValidateStatusMessageFormat(payload []byte) (*StatusMessage, error) {
	if len(payload) < MinStatusMessageSize {
		return nil, fmt.Errorf("%w: status message requires at least %d bytes",
			ErrInvalidMessageFormat, MinStatusMessageSize)
	}

	status := &StatusMessage{
		Version:    binary.BigEndian.Uint32(payload[0:4]),
		NetworkID:  binary.BigEndian.Uint64(payload[4:12]),
		BestHeight: binary.BigEndian.Uint64(payload[12:20]),
	}
	copy(status.BestHash[:], payload[20:52])
	copy(status.GenesisHash[:], payload[52:84])

	// Validate version is reasonable (not zero, not too high)
	if status.Version == 0 {
		return nil, fmt.Errorf("%w: status message version cannot be zero",
			ErrInvalidMessageFormat)
	}

	// SECURITY FIX QPOS-H1: Validate GenesisHash is not zero
	// All nodes must have a configured genesis hash
	var zeroHash [32]byte
	if status.GenesisHash == zeroHash {
		return nil, fmt.Errorf("%w: status message genesis hash cannot be zero",
			ErrInvalidMessageFormat)
	}

	return status, nil
}

// ValidateBlockRequestFormat validates the format of a block request payload
// Requirements: 3.4
func ValidateBlockRequestFormat(payload []byte) (*BlockRequest, error) {
	if len(payload) < MinBlockRequestSize {
		return nil, fmt.Errorf("%w: block request requires at least %d bytes",
			ErrInvalidMessageFormat, MinBlockRequestSize)
	}

	req := &BlockRequest{
		FromHeight: binary.BigEndian.Uint64(payload[0:8]),
		ToHeight:   binary.BigEndian.Uint64(payload[8:16]),
	}

	// Validate height range
	if req.FromHeight > req.ToHeight && req.ToHeight != 0 {
		return nil, fmt.Errorf("%w: block request FromHeight (%d) > ToHeight (%d)",
			ErrInvalidMessageFormat, req.FromHeight, req.ToHeight)
	}

	// audit-fix: enforce maximum block range to prevent DoS via excessive requests
	const maxBlockRange = 64
	if req.ToHeight > 0 && req.ToHeight-req.FromHeight > maxBlockRange {
		return nil, fmt.Errorf("%w: block request range %d exceeds maximum %d",
			ErrInvalidMessageFormat, req.ToHeight-req.FromHeight, maxBlockRange)
	}

	// Validate hash count
	hashCount := binary.BigEndian.Uint32(payload[16:20])
	expectedSize := 20 + int(hashCount)*32
	if len(payload) < expectedSize {
		return nil, fmt.Errorf("%w: block request declares %d hashes but payload size %d is insufficient",
			ErrInvalidMessageFormat, hashCount, len(payload))
	}

	if hashCount > 100 {
		return nil, fmt.Errorf("%w: block request hash count %d exceeds maximum 100",
			ErrInvalidMessageFormat, hashCount)
	}

	// Parse hashes
	req.Hashes = make([][32]byte, hashCount)
	for i := uint32(0); i < hashCount; i++ {
		copy(req.Hashes[i][:], payload[20+i*32:20+(i+1)*32])
	}

	return req, nil
}

// ValidateTxRequestFormat validates the format of a transaction request payload.
// This is P2P message format validation only, checking hash count and payload size.
// Transaction content validation including nonce monotonicity is enforced at txpool admission.
// Requirements: 3.4
// nonce monotonicity enforced at txpool admission
// replay attack protection: chain ID validation enforced at transaction signing (EIP-155)
func ValidateTxRequestFormat(payload []byte) (*TxRequest, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("%w: tx request requires at least 4 bytes",
			ErrInvalidMessageFormat)
	}

	hashCount := binary.BigEndian.Uint32(payload[0:4])
	expectedSize := 4 + int(hashCount)*32
	if len(payload) < expectedSize {
		return nil, fmt.Errorf("%w: tx request declares %d hashes but payload size %d is insufficient",
			ErrInvalidMessageFormat, hashCount, len(payload))
	}

	if hashCount > 100 {
		return nil, fmt.Errorf("%w: tx request hash count %d exceeds maximum 100",
			ErrInvalidMessageFormat, hashCount)
	}

	req := &TxRequest{
		Hashes: make([][32]byte, hashCount),
	}
	for i := uint32(0); i < hashCount; i++ {
		copy(req.Hashes[i][:], payload[4+i*32:4+(i+1)*32])
	}

	return req, nil
}

// MessageValidationResult contains the result of message validation
type MessageValidationResult struct {
	Valid       bool
	Error       error
	MessageType uint8
	PayloadSize uint64
}

// ValidateAndParse validates a message and returns parsed data if applicable
func (v *MessageValidator) ValidateAndParse(msg *Message) (*MessageValidationResult, any) {
	result := &MessageValidationResult{
		Valid:       false,
		MessageType: msg.Type,
		PayloadSize: uint64(len(msg.Payload)),
	}

	if err := v.ValidateMessage(msg); err != nil {
		result.Error = err
		return result, nil
	}

	result.Valid = true

	// Parse specific message types
	switch msg.Type {
	case MsgTypeStatus:
		status, err := ValidateStatusMessageFormat(msg.Payload)
		if err != nil {
			result.Valid = false
			result.Error = err
			return result, nil
		}
		return result, status

	case MsgTypeBlockReq:
		req, err := ValidateBlockRequestFormat(msg.Payload)
		if err != nil {
			result.Valid = false
			result.Error = err
			return result, nil
		}
		return result, req

	case MsgTypeTxReq:
		req, err := ValidateTxRequestFormat(msg.Payload)
		if err != nil {
			result.Valid = false
			result.Error = err
			return result, nil
		}
		return result, req
	}

	return result, nil
}

// ValidateStatusMessageSecurity validates security-critical fields in a status message.
// SECURITY FIX QPOS-H1: Validates GenesisHash matches local configuration.
// SECURITY FIX QPOS-H2: Validates NetworkID matches local configuration.
// This should be called after ValidateStatusMessageFormat during peer handshake.
func ValidateStatusMessageSecurity(status *StatusMessage, expectedNetworkID uint64) error {
	// Validate NetworkID matches
	if status.NetworkID != expectedNetworkID {
		return fmt.Errorf("network ID mismatch: peer has %d, expected %d",
			status.NetworkID, expectedNetworkID)
	}

	// Validate GenesisHash matches local configuration
	var peerGenesisHash types.Hash
	copy(peerGenesisHash[:], status.GenesisHash[:])

	if err := consensus.ValidateGenesisBlockHash(peerGenesisHash); err != nil {
		return fmt.Errorf("genesis hash validation failed: %w", err)
	}

	return nil
}

// SnapStateReqValidator validates snap state request messages
type SnapStateReqValidator struct{}

func (v *SnapStateReqValidator) MaxSize() uint64 { return MaxSnapStateReqSize }
func (v *SnapStateReqValidator) MinSize() uint64 { return 8 }

func (v *SnapStateReqValidator) Validate(payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("%w: snap state request requires at least 8 bytes", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapStateRespValidator validates snap state response messages
type SnapStateRespValidator struct{}

func (v *SnapStateRespValidator) MaxSize() uint64 { return MaxSnapStateRespSize }
func (v *SnapStateRespValidator) MinSize() uint64 { return 4 }

func (v *SnapStateRespValidator) Validate(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("%w: snap state response too short", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapRangeReqValidator validates snap range request messages
type SnapRangeReqValidator struct{}

func (v *SnapRangeReqValidator) MaxSize() uint64 { return MaxSnapRangeReqSize }
func (v *SnapRangeReqValidator) MinSize() uint64 { return 8 }

func (v *SnapRangeReqValidator) Validate(payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("%w: snap range request requires at least 8 bytes", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapRangeRespValidator validates snap range response messages
type SnapRangeRespValidator struct{}

func (v *SnapRangeRespValidator) MaxSize() uint64 { return MaxSnapRangeRespSize }
func (v *SnapRangeRespValidator) MinSize() uint64 { return 4 }

func (v *SnapRangeRespValidator) Validate(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("%w: snap range response too short", ErrInvalidMessageFormat)
	}
	return nil
}

// ETHEREUM-PARITY SYNC (2026-08-13): format validators for the extended
// sync protocol messages. Size bounds are enforced by MaxSize/MinSize;
// Validate performs the fixed-prefix sanity checks.

// SnapStorageReqValidator validates snap storage request messages
type SnapStorageReqValidator struct{}

func (v *SnapStorageReqValidator) MaxSize() uint64 { return MaxSnapStorageReqSize }
func (v *SnapStorageReqValidator) MinSize() uint64 { return 8 + 32 + 32 + 4 }

func (v *SnapStorageReqValidator) Validate(payload []byte) error {
	if len(payload) < 8+32+32+4 {
		return fmt.Errorf("%w: snap storage request too short", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapStorageRespValidator validates snap storage response messages
type SnapStorageRespValidator struct{}

func (v *SnapStorageRespValidator) MaxSize() uint64 { return MaxSnapStorageRespSize }
func (v *SnapStorageRespValidator) MinSize() uint64 { return 8 + 32 + 1 + 4 }

func (v *SnapStorageRespValidator) Validate(payload []byte) error {
	if len(payload) < 8+32+1+4 {
		return fmt.Errorf("%w: snap storage response too short", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapBytecodeReqValidator validates snap bytecode request messages
type SnapBytecodeReqValidator struct{}

func (v *SnapBytecodeReqValidator) MaxSize() uint64 { return MaxSnapBytecodeReqSize }
func (v *SnapBytecodeReqValidator) MinSize() uint64 { return 8 + 4 + 4 }

func (v *SnapBytecodeReqValidator) Validate(payload []byte) error {
	if len(payload) < 8+4+4 {
		return fmt.Errorf("%w: snap bytecode request too short", ErrInvalidMessageFormat)
	}
	return nil
}

// SnapBytecodeRespValidator validates snap bytecode response messages
type SnapBytecodeRespValidator struct{}

func (v *SnapBytecodeRespValidator) MaxSize() uint64 { return MaxSnapBytecodeRespSize }
func (v *SnapBytecodeRespValidator) MinSize() uint64 { return 8 + 1 + 4 }

func (v *SnapBytecodeRespValidator) Validate(payload []byte) error {
	if len(payload) < 8+1+4 {
		return fmt.Errorf("%w: snap bytecode response too short", ErrInvalidMessageFormat)
	}
	return nil
}

// HeaderReqValidator validates header-first sync request messages
type HeaderReqValidator struct{}

func (v *HeaderReqValidator) MaxSize() uint64 { return MaxHeaderReqSize }
func (v *HeaderReqValidator) MinSize() uint64 { return 57 }

func (v *HeaderReqValidator) Validate(payload []byte) error {
	if len(payload) < 57 {
		return fmt.Errorf("%w: header request too short", ErrInvalidMessageFormat)
	}
	count := binary.BigEndian.Uint32(payload[48:52])
	if count == 0 || count > MaxHeaderRequestCount {
		return fmt.Errorf("%w: header request count %d out of range", ErrInvalidMessageFormat, count)
	}
	return nil
}

// HeaderRespValidator validates header-first sync response messages
type HeaderRespValidator struct{}

func (v *HeaderRespValidator) MaxSize() uint64 { return MaxHeaderRespSize }
func (v *HeaderRespValidator) MinSize() uint64 { return 12 }

func (v *HeaderRespValidator) Validate(payload []byte) error {
	if len(payload) < 12 {
		return fmt.Errorf("%w: header response too short", ErrInvalidMessageFormat)
	}
	return nil
}

// ReceiptReqValidator validates receipt request messages
type ReceiptReqValidator struct{}

func (v *ReceiptReqValidator) MaxSize() uint64 { return MaxReceiptReqSize }
func (v *ReceiptReqValidator) MinSize() uint64 { return 12 }

func (v *ReceiptReqValidator) Validate(payload []byte) error {
	if len(payload) < 12 {
		return fmt.Errorf("%w: receipt request too short", ErrInvalidMessageFormat)
	}
	count := binary.BigEndian.Uint32(payload[8:12])
	if count > MaxReceiptRequestCount {
		return fmt.Errorf("%w: receipt request count %d exceeds max %d", ErrInvalidMessageFormat, count, MaxReceiptRequestCount)
	}
	return nil
}

// ReceiptRespValidator validates receipt response messages
type ReceiptRespValidator struct{}

func (v *ReceiptRespValidator) MaxSize() uint64 { return MaxReceiptRespSize }
func (v *ReceiptRespValidator) MinSize() uint64 { return 12 }

func (v *ReceiptRespValidator) Validate(payload []byte) error {
	if len(payload) < 12 {
		return fmt.Errorf("%w: receipt response too short", ErrInvalidMessageFormat)
	}
	return nil
}

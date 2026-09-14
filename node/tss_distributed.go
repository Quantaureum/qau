// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// round2PrivateFreshnessWindow is the maximum allowed |now - msgTimestamp|
// for a Round2 private message (TSS-). 5 minutes covers realistic NTP
// drift across validators while bounding the replay window.
const round2PrivateFreshnessWindow = 5 * time.Minute

// maxRound2PrivateLastTSEntries bounds the size of round2PrivateLastTS to
// prevent memory-exhaustion DoS (TSS-). An attacker can spam
// SessionInit/Round2 messages with fresh (sessionID, participantID) tuples;
// without a cap, the map grows unbounded. 10000 entries × 48 bytes (40 key +
// 8 value) ~= 480 KB, negligible for a node. When the cap is reached, we
// evict stale entries first (older than the freshness window — already
// useless), then oldest entries by timestamp.
const maxRound2PrivateLastTSEntries = 10000

// isAllZeroBytes returns true if every byte in b is 0x00.
// R38-P1-03: Used to reject TSS session init messages that contain an
// all-zero "message to sign", which would allow the proposer to obtain
// a threshold signature on a null hash.
func isAllZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// tssCanonicalBindingDomain is the fixed domain-separation prefix for the
// canonical TSS session init binding hash. R38-P1-03 FIX.
const tssCanonicalBindingDomain = "QAU-TSS-v1"

// tssDomainTagBlock / tssDomainTagVote distinguish the two legitimate uses
// of the distributed TSS oracle so that a signature produced for one purpose
// cannot be replayed as the other. R38-P1-03 FIX.
const (
	tssDomainTagBlock = "block"
	tssDomainTagVote  = "vote"
)

// computeTSSCanonicalBinding derives the 32-byte canonical message that MUST
// be signed by distributed TSS for a given (chainID, epoch, slot, proposer,
// domainTag, originalMessage) tuple. R38-P1-03 FIX.
//
// Audit rationale: A pure proposer-authenticity check (B-5) lets the current
// block proposer ask all participants to threshold-sign ANY 32-byte message.
// Once distributed TSS is enabled (the kill-switch is intentionally opened by
// the operator), the signer becomes an oracle for arbitrary content chosen by
// the proposer — including fake "blocks"/"votes"/"review verdicts" that would
// break finality on instant-finality paths that trust the resulting signature.
//
// Mitigation: bind the signed message to deterministic chain context. Both
// the proposer (when initiating) and the participants (when validating) derive
// the same canonicalMessage from the same chain state. A malicious proposer
// cannot sign anything that is not (chainID || epoch || slot || proposer ||
// domainTag || originalMessage). The originalMessage is preserved in the wire
// so participants can re-derive the binding and verify it on receipt.
//
// Format (SHA-256 input, length-prefixed to avoid concatenation ambiguity):
//
//	"QAU-TSS-v1" || len(chainID)8  || chainID_be8
//	|| len(epoch)8   || epoch_be8
//	|| len(slot)8    || slot_be8
//	|| len(proposer)8|| proposer[20]
//	|| len(domain)8  || domainTag
//	|| len(orig)8    || originalMessage
//
// All length prefixes are 8 bytes big-endian — this is over-specified but
// makes the encoding unambiguous for auditors and prevents the classic
// "different arguments, same concatenated bytes" collision.
func computeTSSCanonicalBinding(chainID, epoch, slot uint64, proposer types.Address, domainTag string, originalMessage []byte) [32]byte {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, uint64(len(tssCanonicalBindingDomain)))
	h.Write([]byte(tssCanonicalBindingDomain))
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, chainID)
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, epoch)
	binary.Write(h, binary.BigEndian, uint64(8))
	binary.Write(h, binary.BigEndian, slot)
	binary.Write(h, binary.BigEndian, uint64(len(proposer)))
	h.Write(proposer[:])
	binary.Write(h, binary.BigEndian, uint64(len(domainTag)))
	h.Write([]byte(domainTag))
	binary.Write(h, binary.BigEndian, uint64(len(originalMessage)))
	h.Write(originalMessage)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// tssSessionInitBindingMagic is a 4-byte sentinel that marks the presence of
// the R38-P1-03 canonical-binding tail in a SessionInit payload. It must be
// distinct from any byte sequence that could legitimately appear at the end
// of a legacy (pre-R38) SessionInit payload (which ends with an 8-byte
// Unix-nano ulong, so any 4 ASCII bytes are safe). R38-P1-03 FIX.
var tssSessionInitBindingMagic = [4]byte{'Q', 'T', 'B', '1'}

// encodeTSSSessionInitBound produces a SessionInit payload that carries the
// canonical binding block appended after the legacy wire frame. R38-P1-03 FIX.
//
// Layout:
//
//	[legacy EncodeSessionInit payload using canonicalMessage as message]
//	[magic 4B] [chainID_be 8] [epoch_be 8] [slot_be 8]
//	[proposerAddr 20] [domainTagLen 1] [domainTag] [origMsgLen 4] [origMsg]
func encodeTSSSessionInitBound(
	sessionID [32]byte,
	canonicalMessage []byte,
	participantIDs []int,
	initiatedAt int64,
	chainID, epoch, slot uint64,
	proposer types.Address,
	domainTag string,
	originalMessage []byte,
) []byte {
	base := tss.EncodeSessionInit(sessionID, canonicalMessage, participantIDs, initiatedAt)
	if len(domainTag) > 255 {
		// Defensive: domain tags are tiny constants. Anything larger indicates
		// a logic error and would overflow the 1-byte length prefix.
		domainTag = domainTag[:255]
	}
	tailLen := 4 + 8 + 8 + 8 + 20 + 1 + len(domainTag) + 4 + len(originalMessage)
	out := make([]byte, len(base)+tailLen)
	copy(out, base)
	off := len(base)
	copy(out[off:off+4], tssSessionInitBindingMagic[:])
	off += 4
	binary.BigEndian.PutUint64(out[off:off+8], chainID)
	off += 8
	binary.BigEndian.PutUint64(out[off:off+8], epoch)
	off += 8
	binary.BigEndian.PutUint64(out[off:off+8], slot)
	off += 8
	copy(out[off:off+20], proposer[:])
	off += 20
	out[off] = byte(len(domainTag))
	off++
	copy(out[off:off+len(domainTag)], domainTag)
	off += len(domainTag)
	binary.BigEndian.PutUint32(out[off:off+4], uint32(len(originalMessage)))
	off += 4
	copy(out[off:off+len(originalMessage)], originalMessage)
	return out
}

// tssSessionInitBinding carries the decoded R38-P1-03 binding block.
type tssSessionInitBinding struct {
	chainID         uint64
	epoch           uint64
	slot            uint64
	proposer        types.Address
	domainTag       string
	originalMessage []byte
}

// decodeTSSSessionInitBound splits a SessionInit payload into:
//   - the legacy frame (used by tss.DecodeSessionInit to recover sessionID,
//     canonicalMessage, participantIDs, initiatedAt)
//   - the R38-P1-03 binding block (or nil if the payload is legacy v1)
//
// Returns (legacyFrame, binding, ok). When ok==false, the payload is too short
// to carry the magic; callers treat it as a legacy pre-R38 frame.
func decodeTSSSessionInitBound(payload []byte) (legacyFrame []byte, binding *tssSessionInitBinding, ok bool) {
	// tailMin is the minimum byte count the binding tail must occupy.
	// Layout: magic(4) + chainID(8) + epoch(8) + slot(8) + proposer(20) +
	// domainTagLen(1) + domainTag(varies) + origMsgLen(4) + origMsg(varies).
	// With domainTag empty and origMsg empty: 4+8+8+8+20+1+0+4+0 = 53.
	// We compute tailMin dynamically below as the smallest possible tail.
	const magicLen = 4
	const chainIDLen, epochLen, slotLen = 8, 8, 8
	const proposerLen = 20
	const domainTagLenField = 1
	const origMsgLenField = 4
	tailMin := magicLen + chainIDLen + epochLen + slotLen + proposerLen + domainTagLenField + origMsgLenField
	// The minimum required for ANY binding presence (incl. magic).
	if len(payload) < tailMin {
		// Definitely too short to contain a binding tail.
		return payload, nil, false
	}
	// Search the LAST occurrence of the 4-byte magic to be robust against
	// any chance pattern appearing inside the legacy frame. In practice the
	// legacy frame length is fixed for a given (msg, participants, ts).
	magicAt := bytes.LastIndex(payload, tssSessionInitBindingMagic[:])
	if magicAt < 0 {
		// No binding tail present — legacy v1 payload.
		return payload, nil, false
	}
	// The binding tail begins exactly after the magic.
	tail := payload[magicAt+4:]
	if len(tail) < tailMin-magicLen {
		// Magic present but tail truncated — treat as legacy (and let the
		// downstream length check reject). We must not slice out-of-range.
		return payload, nil, false
	}
	off := 0
	chainID := binary.BigEndian.Uint64(tail[off : off+8])
	off += 8
	epoch := binary.BigEndian.Uint64(tail[off : off+8])
	off += 8
	slot := binary.BigEndian.Uint64(tail[off : off+8])
	off += 8
	var proposer types.Address
	copy(proposer[:], tail[off:off+20])
	off += 20
	if len(tail) < off+1 {
		return payload, nil, false
	}
	domainTagLen := int(tail[off])
	off++
	if len(tail) < off+domainTagLen+4 {
		return payload, nil, false
	}
	domainTag := string(tail[off : off+domainTagLen])
	off += domainTagLen
	origMsgLen := int(binary.BigEndian.Uint32(tail[off : off+4]))
	off += 4
	if len(tail) < off+origMsgLen {
		return payload, nil, false
	}
	origMsg := make([]byte, origMsgLen)
	copy(origMsg, tail[off:off+origMsgLen])

	// Sanity: the bytes BEFORE magic must be parseable bytewise as the
	// legacy frame. There is no internal length field in the v1 format we can
	// use to assert this; the magic search heuristic above is the best we have.
	// Reject if the recovered "legacyFrame" is empty (impossible for a real
	// SessionInit). Otherwise trust the magic position.
	legacyFrame = payload[:magicAt]
	if len(legacyFrame) == 0 {
		return payload, nil, false
	}
	return legacyFrame, &tssSessionInitBinding{
		chainID:         chainID,
		epoch:           epoch,
		slot:            slot,
		proposer:        proposer,
		domainTag:       domainTag,
		originalMessage: origMsg,
	}, true
}

// This file implements the node-level TSS message processing loop.
//
// When TSSDistributedMode is enabled, the node subscribes to TSS P2P messages
// and coordinates distributed threshold signing with other validator nodes.
//
// True distributed flow (each node computes only its own share):
//
//   AGGREGATOR (block proposer):
//   1. InitiateSession → broadcast SessionInit
//   2. Compute own Round1 commitment + W_i → broadcast Round1Commit
//   3. Wait for all Round1 commitments (with W_i from each participant)
//   4. Compute own Round2 reveal → broadcast public part, send private encrypted to self
//   5. Wait for threshold Round2 reveals from participants
//   6. AggregateSignature → broadcast final signature
//
//   PARTICIPANT (non-proposer):
//   1. Receive SessionInit → create local participant session
//   2. Compute own Round1 commitment + W_i → broadcast Round1Commit
//   3. Collect other participants' Round1 commitments + W_i
//   4. Once Round1 complete → compute own Round2 reveal
//   5. Send public part to aggregator (broadcast), private part encrypted to aggregator
//   6. Receive final signature

// tssProcessingLoop consumes TSS messages from the P2P layer and routes them
// to the distributed signer for processing.
func (n *Node) tssProcessingLoop() {
	defer n.wg.Done()
	// NODE-P2-01 FIX (R31, 2026-07-28): top-level panic recovery so a single
	// unrecovered panic cannot silently disable TSS message processing, which
	// would stall distributed key generation and block finality.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("tssProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	if n.distributedSigner == nil || n.p2pHost == nil {
		return
	}

	tssCh := n.p2pHost.SubscribeTSS()
	cleanupTicker := time.NewTicker(10 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case msg := <-tssCh:
			// NODE-P2-01 FIX (R31, 2026-07-28): per-message recover so a
			// malformed message or a bug in handleTSSMessage does not kill
			// the entire TSS loop. Subsequent messages must still be
			// processed; losing the loop permanently would stall finality.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("tssProcessingLoop: message handler panic recovered (msg type=%d, continuing): %v", msg.Type, r)
					}
				}()
				n.handleTSSMessage(msg)
			}()

		case <-cleanupTicker.C:
			// NODE-P2-01 FIX (R31, 2026-07-28): per-tick recover for the
			// cleanup path. CleanExpiredSessions touches session maps and
			// may panic on corrupted state; the next tick should retry.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("tssProcessingLoop: cleanup panic recovered (continuing): %v", r)
					}
				}()
				n.distributedSigner.CleanExpiredSessions()
			}()
		}
	}
}

// handleTSSMessage processes a single TSS P2P message based on its type.
//
// Task 5 (TSSDistributedDKG): distributed DKG round messages (77/78) are
// routed to the coordinator's P2P transport first, independent of
// TSSDistributedMode — a node can run a multi-party DKG round (TSSDistributed
// DKG) without enabling the legacy distributed-signing path.
func (n *Node) handleTSSMessage(msg p2p.PeerMessage) {
	switch msg.Type {
	case p2p.MsgTypeTSSDKGCommitment:
		n.handleTSSDKGCommitment(msg)
		return

	case p2p.MsgTypeTSSDKGAck:
		n.handleTSSDKGShare(msg)
		return
	}

	// The legacy distributed-signing handlers below require a
	// DistributedSigner (TSSDistributedMode=true). When only distributed DKG
	// is enabled (TSSDistributedDKG=true without TSSDistributedMode), there
	// is no signing state to operate on — ignore such messages instead of
	// invoking handlers against a nil signer.
	if n.distributedSigner == nil {
		nodeLog.Debug("TSS message type %d ignored: distributed signing not enabled (TSSDistributedMode off)", msg.Type)
		return
	}

	switch msg.Type {
	case p2p.MsgTypeTSSSessionInit:
		n.handleTSSSessionInit(msg)

	case p2p.MsgTypeTSSRound1Commit:
		n.handleTSSRound1Commit(msg)

	case p2p.MsgTypeTSSRound2Reveal:
		n.handleTSSRound2Reveal(msg)

	case p2p.MsgTypeTSSRound2Private:
		n.handleTSSRound2Private(msg)

	case p2p.MsgTypeTSSSignature:
		n.handleTSSSignature(msg)

	case p2p.MsgTypeTSSKeyExchange:
		n.handleTSSKeyExchange(msg)

	case p2p.MsgTypeTSSDKGShare:
		nodeLog.Debug("TSS DKG share received from peer (size=%d)", len(msg.Payload))

	default:
		nodeLog.Warn("Unknown TSS message type %d from peer", msg.Type)
	}
}

// handleTSSDKGCommitment routes an incoming distributed DKG Round1 commitment
// (p2p.MsgTypeTSSDKGCommitment) to the coordinator's transport. When
// distributed DKG is not enabled (TSSDistributedDKG off, the default), no
// coordinator exists and the message is ignored — the node never subscribes
// in that case, so this is defensive only.
func (n *Node) handleTSSDKGCommitment(msg p2p.PeerMessage) {
	if n.dkgCoordinator == nil {
		nodeLog.Debug("DKG commitment ignored: distributed DKG not enabled (TSSDistributedDKG off)")
		return
	}
	commit, err := decodeDKGCommitmentPayload(msg.Payload)
	if err != nil {
		nodeLog.Warn("DKG commitment decode error: %v", err)
		return
	}
	// AUDIT TSS B-3: bind sender to participant ID so an unauthenticated
	// peer cannot inject a bogus commitment for another participant.
	if !n.validateDKGMessageSender(msg.From, commit.ParticipantID) {
		nodeLog.Warn("DKG commitment: sender %v does not match participantID %d, rejecting (B-3)",
			msg.From, commit.ParticipantID)
		return
	}
	n.dkgCoordinator.Transport().IngestCommitment(commit)
	nodeLog.Debug("DKG commitment ingested from participant %d (commitSize=%d)",
		commit.ParticipantID, len(commit.Commitment))
}

// handleTSSDKGShare routes an incoming distributed DKG Round1 open + share
// (p2p.MsgTypeTSSDKGAck) to the coordinator's transport.
func (n *Node) handleTSSDKGShare(msg p2p.PeerMessage) {
	if n.dkgCoordinator == nil {
		nodeLog.Debug("DKG share ignored: distributed DKG not enabled (TSSDistributedDKG off)")
		return
	}
	share, err := decodeDKGSharePayload(msg.Payload)
	if err != nil {
		nodeLog.Warn("DKG share decode error: %v", err)
		return
	}
	// AUDIT TSS B-3: bind sender to participant ID. Shares are private key
	// material — a spoofed participant ID here could inject a forged share.
	if !n.validateDKGMessageSender(msg.From, share.ParticipantID) {
		nodeLog.Warn("DKG share: sender %v does not match participantID %d, rejecting (B-3)",
			msg.From, share.ParticipantID)
		return
	}
	n.dkgCoordinator.Transport().IngestShare(share)
	nodeLog.Debug("DKG share ingested from participant %d", share.ParticipantID)
}

// validateDKGMessageSender binds a DKG message's sender peer to the claimed
// participant ID using the validator↔peer map, mirroring the existing TSS
// handlers (AUDIT (2026) TSS B-3). Returns false when the sender cannot
// be resolved to a validator or the participant ID does not match.
func (n *Node) validateDKGMessageSender(from p2p.PeerID, claimedPID int) bool {
	senderAddr, found := n.resolveSenderAddress(from)
	if !found {
		return false
	}
	return n.validateSenderParticipantID(senderAddr, claimedPID)
}

// getMyParticipantID returns this node's TSS participant ID (1-based).
// It maps the validator index to a 1-based share ID.
func (n *Node) getMyParticipantID() int {
	if n.blockProducer == nil {
		return -1
	}
	idx := n.blockProducer.findValidatorIndex()
	if idx < 0 {
		return -1
	}
	return idx + 1 // TSS participant IDs are 1-based
}

// isAggregator returns true if this node is the current block proposer.
func (n *Node) isAggregator() bool {
	if n.blockProducer == nil {
		return false
	}
	slot := n.blockProducer.GetCurrentSlot()
	isProposer, _ := n.blockProducer.isProposerForSlot(slot)
	return isProposer
}

// validateSenderParticipantID verifies that the sender's validator address
// maps to the claimed participantID. This prevents share hijacking and
// injection attacks where a malicious peer claims another participant's ID.
// AUDIT (2026) TSS B-3: sender ↔ participantID binding.
func (n *Node) validateSenderParticipantID(senderAddr types.Address, claimedPID int) bool {
	if n.blockProducer == nil || n.blockProducer.qpos == nil {
		return false
	}
	vs := n.blockProducer.qpos.GetValidatorSet()
	if vs == nil {
		return false
	}
	validators := vs.Validators()
	for i, v := range validators {
		if bytes.Equal(v.Address[:], senderAddr[:]) {
			return (i + 1) == claimedPID // TSS participant IDs are 1-based
		}
	}
	return false
}

// resolveSenderAddress resolves a PeerID to a validator address using the
// P2P host's validator-peer map. Returns false if not found.
func (n *Node) resolveSenderAddress(peerID p2p.PeerID) (types.Address, bool) {
	if n.p2pHost == nil {
		return types.Address{}, false
	}
	return n.p2pHost.GetValidatorForPeer(peerID)
}

// setAggregatorSession records the current aggregator session ID.
// AUDIT (2026) TSS B-4: Only the aggregator sets this; it's cleared
// when the session completes or expires. Shares for other sessions are
// rejected to prevent cross-session share misdelivery.
func (n *Node) setAggregatorSession(sessionID []byte) {
	n.aggregatorSessionMu.Lock()
	defer n.aggregatorSessionMu.Unlock()
	n.currentAggregatorSession = sessionID
}

// isCurrentAggregatorSession checks whether the given sessionID matches
// the current aggregator session.
func (n *Node) isCurrentAggregatorSession(sessionID []byte) bool {
	n.aggregatorSessionMu.Lock()
	defer n.aggregatorSessionMu.Unlock()
	if len(n.currentAggregatorSession) == 0 {
		return true // No tracking enabled — accept (backward compat)
	}
	return bytes.Equal(n.currentAggregatorSession, sessionID)
}

// clearAggregatorSession clears the current aggregator session tracking.
// TSS-FIX (2026-07-17): also drop per-(session, participant) replay
// timestamps so a future session reusing the same ID (unlikely but possible)
// starts from a clean monotonic baseline.
func (n *Node) clearAggregatorSession() {
	n.aggregatorSessionMu.Lock()
	cleared := n.currentAggregatorSession
	n.currentAggregatorSession = nil
	n.aggregatorSessionMu.Unlock()

	if cleared != nil {
		n.round2PrivateTSMu.Lock()
		for k := range n.round2PrivateLastTS {
			// Only clear entries for the session being torn down. Entries for
			// other (concurrent) sessions are preserved.
			var sid [32]byte
			copy(sid[:], k[0:32])
			if bytes.Equal(sid[:], cleared) {
				delete(n.round2PrivateLastTS, k)
			}
		}
		n.round2PrivateTSMu.Unlock()
	}
}

// validateRound2PrivateFreshness enforces the TSS- freshness window and
// per-(session, participant) strict-monotonic-increase check on an incoming
// Round2 private message. Returns true if the message is fresh and may be
// processed; returns false (after logging) if it must be dropped.
//
// This method is extracted from handleTSSRound2Private so that the freshness
// state machine can be unit-tested in isolation without standing up the full
// P2P / keyExchange / distributedSigner stack.
//
// Side effect: on success, updates round2PrivateLastTS[sessionID||pid] =
// msgTimestamp so subsequent replays are rejected.
func (n *Node) validateRound2PrivateFreshness(sessionID [32]byte, participantID int, msgTimestamp int64) bool {
	nowNs := time.Now().UnixNano()
	delta := nowNs - msgTimestamp
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(round2PrivateFreshnessWindow) {
		nodeLog.Warn("TSS Round2 private: freshness window violated (delta=%d ns > %d) for session=%x pid=%d — rejecting (TSS-)",
			delta, int64(round2PrivateFreshnessWindow), sessionID[:8], participantID)
		return false
	}

	// Build composite key [32 sessionID bytes + 8 participantID bytes].
	var tsKey [40]byte
	copy(tsKey[0:32], sessionID[:])
	binary.BigEndian.PutUint64(tsKey[32:40], uint64(participantID))

	n.round2PrivateTSMu.Lock()
	defer n.round2PrivateTSMu.Unlock()
	prev, seen := n.round2PrivateLastTS[tsKey]
	if seen && msgTimestamp <= prev {
		nodeLog.Warn("TSS Round2 private: non-monotonic timestamp (msg=%d, prev=%d) for session=%x pid=%d — rejecting (TSS-)",
			msgTimestamp, prev, sessionID[:8], participantID)
		return false
	}
	// TSS-FIX: Bound map size to prevent memory-exhaustion DoS.
	// When the cap is reached, prune stale entries (older than the
	// freshness window — already useless) before adding a new one. If
	// stale entries don't free enough slots, evict oldest-by-timestamp.
	if len(n.round2PrivateLastTS) >= maxRound2PrivateLastTSEntries {
		n.pruneRound2PrivateLastTSLocked(nowNs)
	}
	n.round2PrivateLastTS[tsKey] = msgTimestamp
	return true
}

// pruneRound2PrivateLastTSLocked evicts entries from round2PrivateLastTS to
// bring it under the cap. Caller MUST hold round2PrivateTSMu.
// Strategy (in order):
//  1. Drop stale entries whose timestamp is older than the freshness window
//     — these are already useless for replay protection.
//  2. If still at/over cap, drop the oldest entries by timestamp, BUT skip
//     entries updated within the "active" sub-window (TSS-M9 FIX). This
//     protects active sessions whose Round2 messages were exchanged
//     recently — even if the map is full, an attacker cannot force us to
//     evict replay-protection entries for sessions that are still in flight.
//
// TSS-M9 (R8 2026-07-19) FIX: Previously step 2 evicted strictly oldest-
// by-timestamp, which could evict entries belonging to slow-but-active
// sessions, causing their subsequent Round2 messages to be rejected as
// non-monotonic. The active sub-window (1 minute = freshnessWindow/5)
// protects entries younger than 1 minute. If ALL remaining entries are
// within the active sub-window, eviction falls back to oldest-by-timestamp
// to honor the memory bound (and logs a warning).
//
// Practical impact: An attacker would need to sustain >10000 active
// entries within 1 minute to force harmful eviction. B-5 (only the current
// slot proposer can initiate SessionInit) limits this to ~5 sessions/min,
// so the fallback path is effectively unreachable on mainnet.
func (n *Node) pruneRound2PrivateLastTSLocked(nowNs int64) {
	staleThreshold := nowNs - int64(round2PrivateFreshnessWindow)
	for k, ts := range n.round2PrivateLastTS {
		if ts < staleThreshold {
			delete(n.round2PrivateLastTS, k)
		}
	}
	// activeThreshold: entries updated after this are considered "active" and
	// are protected from eviction in step 2's first pass.
	const activeSubWindow = round2PrivateFreshnessWindow / 5 // 1 minute
	activeThreshold := nowNs - int64(activeSubWindow)

	// Pass 1: evict oldest-by-timestamp, skipping entries within active sub-window.
	for len(n.round2PrivateLastTS) >= maxRound2PrivateLastTSEntries {
		var oldestKey [40]byte
		var oldestTS int64
		first := true
		for k, ts := range n.round2PrivateLastTS {
			if ts >= activeThreshold {
				continue // TSS-M9: protect active session entries.
			}
			if first || ts < oldestTS {
				oldestKey = k
				oldestTS = ts
				first = false
			}
		}
		if first {
			// No evictable entries outside active sub-window — fall back to
			// oldest-by-timestamp across ALL entries to honor the memory bound.
			// This path is effectively unreachable on mainnet due to B-5, but
			// we keep it as a hard safety valve.
			nodeLog.Warn("TSS-M9: round2PrivateLastTS still over cap after protecting active sub-window — falling back to oldest-by-timestamp eviction")
			for k, ts := range n.round2PrivateLastTS {
				if first || ts < oldestTS {
					oldestKey = k
					oldestTS = ts
					first = false
				}
			}
			if first {
				return
			}
		}
		delete(n.round2PrivateLastTS, oldestKey)
	}
}

// verifyTSSSessionInitBinding enforces the R38-P1-03 canonical binding
// invariant on an incoming SessionInit message. R38-P1-03 FIX.
//
// Participants do NOT trust the binding's chainID/epoch/slot/proposer:
// these are re-derived from local consensus state (passed as args) and
// cross-checked against the binding. Only (domainTag, originalMessage) are
// taken from the binding — the proposer legitimately controls these. The
// binding's declared canonicalMessage (the wire-level `message` decoded from
// the legacy SessionInit frame) is then verified to equal the SHA-256
// envelope recomputed from the (local) chain context + binding's domainTag +
// originalMessage. A malicious proposer cannot sign anything that is not
// bound to its own chain view, eliminating the oracle attack surface.
//
// Returns (true, "") on success; (false, reason) on rejection. The reason is
// a short string suitable for logging.
func verifyTSSSessionInitBinding(
	binding *tssSessionInitBinding,
	message []byte,
	localChainID uint64,
	localSlot uint64,
	localProposer types.Address,
) (bool, string) {
	// R38-P1-03: Reject legacy v1 SessionInit payloads once distributed TSS
	// is enabled at all (the operator has opened the kill-switch); bound
	// sessions are the ONLY acceptable form from this point forward.
	if binding == nil {
		return false, "missing R38-P1-03 canonical binding tail (oracle attack surface)"
	}

	epoch := localSlot / consensus.SlotsPerEpoch

	// Cross-check chainID: the binding's chainID must equal local chainID.
	if localChainID != 0 && binding.chainID != localChainID {
		return false, fmt.Sprintf("binding chainID %d != local chainID %d (cross-chain)",
			binding.chainID, localChainID)
	}

	// Cross-check epoch + slot: the binding epoch must equal the
	// participant's view (slot/SlotsPerEpoch) for the current slot.
	// Rejects future-epoch / past-epoch Frankensteins the proposer might
	// craft to escape per-slot uniqueness.
	if binding.slot != localSlot || binding.epoch != epoch {
		return false, fmt.Sprintf("binding (slot=%d, epoch=%d) != local (slot=%d, epoch=%d)",
			binding.slot, binding.epoch, localSlot, epoch)
	}

	// Cross-check proposer: the binding's proposer must equal the elected
	// proposer for the current slot. B-5 already guaranteed the SENDER is
	// this proposer; we additionally require the BINDING to assert the
	// same identity so participants that compute canonicalMessage on the
	// other side derive SAME input for the proposer.
	if binding.proposer != localProposer {
		return false, fmt.Sprintf("binding proposer %x != elected proposer %x",
			binding.proposer[:8], localProposer[:8])
	}

	// Re-derive the canonicalMessage from the local view + the binding's
	// (domainTag, originalMessage), which are the two fields that the
	// proposer legitimately controls. Then require the incoming wire-level
	// message (decoded from the legacy SessionInit frame) to EQUAL this
	// recomputed envelope — anything else means the proposer did not run
	// our canonical binder, indicating an oracle attack attempt.
	expectedCanonical := computeTSSCanonicalBinding(
		localChainID, epoch, localSlot, localProposer,
		binding.domainTag, binding.originalMessage,
	)
	if !bytes.Equal(expectedCanonical[:], message) {
		return false, "canonical binding mismatch (oracle binding violated)"
	}

	// Domain tag whitelist. The distributed TSS oracle may ONLY be invoked
	// for the two legitimate in-protocol signing purposes; any other tag
	// (or empty) is rejected as out-of-scope oracle abuse.
	if binding.domainTag != tssDomainTagBlock && binding.domainTag != tssDomainTagVote {
		return false, fmt.Sprintf("unknown domain tag %q (domain whitelist)", binding.domainTag)
	}

	return true, ""
}

// handleTSSSessionInit processes a session initialization broadcast from the aggregator.
// Participants create a local session and compute their own Round1 commitment.
// AUDIT (2026) TSS B-5: SessionInit must be authenticated — only the
// current block proposer (aggregator) is allowed to initiate TSS sessions.
// Any peer broadcasting SessionInit would force all participants into
// expensive computation (Gaussian sampling, matrix multiplication) and
// eventually leak private shares to the "aggregator" address.
//
// R38-P1-03 FIX (2026-08-01): In addition to B-5 (sender == current proposer),
// the message being signed is now bound to canonical chain context:
// chainID || epoch || slot || proposer || domainTag || originalMessage.
// The proposer-side canonicalMessage replaces the original message on the
// wire (in encodeTSSSessionInitBound), and the binding block is appended to
// carry the chain context + the original message. Participants re-derive the
// canonicalMessage locally from the binding block and the participant's own
// view of (chainID, epoch, slot, proposer), then verify it EQUALS the message
// decoded from the legacy frame. This blocks the "proposer as arbitrary
// signing oracle" attack — a malicious proposer cannot sign anything that
// does not deterministically correspond to its own chain view.
func (n *Node) handleTSSSessionInit(msg p2p.PeerMessage) {
	// R38-P1-03: Strip the optional binding tail before handing the legacy
	// frame to tss.DecodeSessionInit. preR38Frame is the legacy wire frame
	// (possibly equal to msg.Payload if no binding tail is present).
	preR38Frame, binding, _ := decodeTSSSessionInitBound(msg.Payload)

	sessionID, message, participantIDs, initiatedAt, err := tss.DecodeSessionInit(preR38Frame)
	if err != nil {
		nodeLog.Warn("TSS session init decode error: %v", err)
		return
	}

	// R38-P1-03 FIX: Validate the message to sign so the proposer cannot
	// use participants as a signing oracle for arbitrary content.
	// The legitimate use case is signing block hashes (32 bytes) or vote
	// messages. We enforce:
	//   1. Message length must be exactly 32 bytes (a block hash or a
	//      vote hash). Anything else is suspicious.
	//   2. Message must not be all-zero (would allow signing a null hash).
	//   3. InitiatedAt must be within a reasonable freshness window of
	//      the participant's local clock to prevent replay of old sessions.
	if len(message) != 32 {
		nodeLog.Warn("TSS session init: rejecting — message length %d is not 32 bytes (R38-P1-03)", len(message))
		return
	}
	if isAllZeroBytes(message) {
		nodeLog.Warn("TSS session init: rejecting — message is all-zero (R38-P1-03)")
		return
	}
	// R38-P1-03: Freshness check — reject sessions with stale or future
	// timestamps to prevent replay. Allow 5 minutes of clock skew.
	if initiatedAt != 0 {
		now := time.Now().UnixNano()
		delta := now - initiatedAt
		if delta < 0 {
			delta = -delta
		}
		if delta > int64(5*time.Minute) {
			nodeLog.Warn("TSS session init: rejecting — initiatedAt is %d ns from local clock (R38-P1-03)", delta)
			return
		}
	}

	// AUDIT (2026) TSS B-5: Verify the sender is the current block proposer.
	// Without this, any peer can force all participants into expensive TSS
	// computation and trigger private share leakage.
	if n.blockProducer != nil {
		slot := n.blockProducer.GetCurrentSlot()
		isProposer, proposerAddr := n.blockProducer.isProposerForSlot(slot)
		if !isProposer {
			nodeLog.Warn("TSS session init: rejecting — current slot has no proposer (B-5)")
			return
		}
		senderAddr, found := n.resolveSenderAddress(msg.From)
		if !found {
			nodeLog.Warn("TSS session init: rejecting — cannot resolve sender address (B-5)")
			return
		}
		if !bytes.Equal(senderAddr[:], proposerAddr[:]) {
			nodeLog.Warn("TSS session init: rejecting — sender %x is not the current proposer %x (B-5)",
				senderAddr[:8], proposerAddr[:8])
			return
		}

		// R38-P1-03 FIX: Canonical binding verification. Defers to a
		// standalone helper see verifyTSSSessionInitBinding below — the
		// helper has no P2P / consensus dependencies so it can be unit
		// tested in isolation; this call site only supplies the local view.
		if ok, reason := verifyTSSSessionInitBinding(
			binding, message,
			n.chainID, slot, proposerAddr,
		); !ok {
			nodeLog.Warn("TSS session init: rejecting — %s (R38-P1-03)", reason)
			return
		}
	}

	// Check if we are a participant
	myPID := n.getMyParticipantID()
	if myPID < 0 {
		nodeLog.Debug("TSS session init: not a validator, ignoring")
		return
	}

	found := false
	for _, pid := range participantIDs {
		if pid == myPID {
			found = true
			break
		}
	}
	if !found {
		nodeLog.Debug("TSS session init: not in participant list (pid=%d), ignoring", myPID)
		return
	}

	// Don't re-process if we're the aggregator (we already initiated)
	if n.isAggregator() {
		return
	}

	// Create local participant session
	if err := n.distributedSigner.InitiateParticipantSession(sessionID, message, participantIDs, myPID, initiatedAt); err != nil {
		nodeLog.Warn("TSS session init: create participant session failed: %v", err)
		return
	}

	nodeLog.Info("TSS participant session created: session=%x, pid=%d", sessionID[:8], myPID)

	// Compute own Round1 commitment + W_i and broadcast
	commitment, wBytes, err := n.distributedSigner.ComputeRound1Commitment(sessionID, myPID)
	if err != nil {
		nodeLog.Warn("TSS session init: compute Round1 failed: %v", err)
		return
	}

	// Submit own commitment locally
	n.distributedSigner.SubmitRound1Commitment(sessionID, commitment)
	n.distributedSigner.SubmitRound1W(sessionID, myPID, wBytes)

	// Broadcast Round1 commitment + W_i to all participants
	commitData, err := tss.EncodeRound1Commitment(sessionID, commitment, wBytes)
	if err != nil {
		nodeLog.Warn("TSS session init: encode Round1 commit failed: %v", err)
		return
	}
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSRound1Commit, commitData); err != nil {
		nodeLog.Warn("TSS session init: broadcast Round1 failed: %v", err)
	}

	// Try to compute Round2 if Round1 is already complete
	n.tryComputeRound2(sessionID, myPID)

	nodeLog.Info("TSS Round1 commitment broadcast: session=%x, pid=%d", sessionID[:8], myPID)
}

// handleTSSRound1Commit processes a Round1 commitment + W_i from another participant.
// AUDIT (2026) TSS B-3: Verify the sender's validator address maps to
// the claimed participantID, preventing share hijacking.
func (n *Node) handleTSSRound1Commit(msg p2p.PeerMessage) {
	sessionID, commitment, wShare, err := tss.DecodeRound1Commitment(msg.Payload)
	if err != nil {
		nodeLog.Warn("TSS Round1 commit decode error: %v", err)
		return
	}

	// AUDIT (2026) TSS B-3: Bind sender to participantID.
	senderAddr, found := n.resolveSenderAddress(msg.From)
	if !found {
		nodeLog.Warn("TSS Round1 commit: cannot resolve sender address, rejecting (B-3)")
		return
	}
	if !n.validateSenderParticipantID(senderAddr, commitment.ParticipantID) {
		nodeLog.Warn("TSS Round1 commit: sender %x does not match participantID %d, rejecting (B-3)",
			senderAddr[:8], commitment.ParticipantID)
		return
	}

	// Store the commitment
	if err := n.distributedSigner.SubmitRound1Commitment(sessionID, commitment); err != nil {
		nodeLog.Warn("TSS Round1 commit submit error: %v", err)
		return
	}

	// Store the W_i for challenge computation
	if err := n.distributedSigner.SubmitRound1W(sessionID, commitment.ParticipantID, wShare); err != nil {
		nodeLog.Warn("TSS Round1 W submit error: %v", err)
		return
	}

	nodeLog.Debug("TSS Round1 commitment + W received: session=%x, participant=%d, wSize=%d",
		sessionID[:8], commitment.ParticipantID, len(wShare))

	// If we're a participant (not aggregator) and Round1 is now complete, compute Round2
	myPID := n.getMyParticipantID()
	if myPID > 0 && !n.isAggregator() {
		n.tryComputeRound2(sessionID, myPID)
	}
}

// tryComputeRound2 checks if Round1 is complete and, if so, computes and sends Round2 reveal.
// Called by participants after receiving each Round1 commitment.
func (n *Node) tryComputeRound2(sessionID [32]byte, myPID int) {
	if !n.distributedSigner.IsRound1Complete(sessionID) {
		return
	}

	reveal, err := n.distributedSigner.ComputeRound2Reveal(sessionID, myPID)
	if err != nil {
		nodeLog.Warn("TSS Round2 compute failed: %v", err)
		return
	}

	// Broadcast public part (WShare + ZShare + Nonce)
	revealData := tss.EncodeRound2RevealPublic(sessionID, reveal)
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSRound2Reveal, revealData); err != nil {
		nodeLog.Warn("TSS Round2 broadcast public failed: %v", err)
	}

	// Send private part (ZShare + combined z0 contribution Z0Share) encrypted to the aggregator
	n.sendPrivateRound2(sessionID, myPID, reveal)

	nodeLog.Info("TSS Round2 reveal sent: session=%x, pid=%d", sessionID[:8], myPID)
}

// sendPrivateRound2 encrypts and sends the private Round2 data to the aggregator.
//
// SECURITY (P0 fix): Private signing material (ZShare + combined z0 contribution
// Z0Share) is encrypted using one-shot Kyber768 KEM + AES-256-GCM before P2P
// transport. The encrypted payload is sent point-to-point to the aggregator via
// SendTSSToValidator, NOT broadcast. If encryption fails, the data is NOT sent
// (fail-closed) — the TSS session will timeout and fall back to local signing.
//
// AUDIT (2026) TSS-FIX (CRITICAL): The previous design transmitted
// SEPARATE masked contributions Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i).
// This was catastrophically insecure: the challenge polynomial c is invertible
// in the NTT ring Z_q[X]/(X^256+1), so the aggregator could recover s2 and t0
// by NTT inversion, then s1 via A·s1 = t - s2, reconstructing the FULL private
// key. The new design transmits a SINGLE combined Z0Share = λ_i·c·(t0_i - s2_i)
// which the aggregator CANNOT decompose into c·s2 and c·t0 separately.
//
// RESIDUAL RISK (High): The aggregator can still recover s1 from the aggregated
// Z0Share because c·(t0-s2) = c·(A·s1 - t1·2^d). However, the aggregator CANNOT
// recover s2 or t0 individually, so it CANNOT forge signatures. Full closure
// requires DH-based pairwise masking or distributed hint generation. Until then,
// distributed TSS is HARD-BLOCKED in production (see distributedTSSEnabled()).
//
// Raw secret-key shares (S2Share/T0Share) are NEVER transmitted over the wire.
// The old ScShare (λ_i·s1_i·c) transmission is also removed — it leaked s1.
func (n *Node) sendPrivateRound2(sessionID [32]byte, pid int, reveal *qtd.Round2Reveal) {
	// AUDIT (2026) TSS-FIX: Send the combined Z0Share directly from
	// the reveal. No need to fetch raw S2/T0 shares — they are computed locally
	// inside Round2Reveal() and never leave the node in raw form.
	// R2-HIGH-07: ZShare is also sent via the private channel.
	// TSS-FIX (2026-07-17): Embed a Unix-nano freshness timestamp so the
	// aggregator can reject intra-session replays (same ciphertext replayed by
	// a malicious relay within the B-3/B-4 window). The aggregator enforces
	// strict per-(session, participant) monotonic increase.
	privateData, err := tss.EncodeRound2RevealPrivate(sessionID, pid, time.Now().UnixNano(), reveal.ZShare, reveal.Z0Share)
	if err != nil {
		nodeLog.Error("SECURITY: TSS sendPrivateRound2: encode private reveal failed for pid=%d: %v — private data NOT sent (fail-closed)", pid, err)
		return
	}

	if n.keyExchange == nil {
		nodeLog.Error("SECURITY: TSS sendPrivateRound2: keyExchange is nil — private data NOT sent (fail-closed). " +
			"TSS encrypted transport must be initialized before distributed signing.")
		return
	}

	if n.blockProducer == nil {
		nodeLog.Error("SECURITY: TSS sendPrivateRound2: blockProducer is nil — private data NOT sent (fail-closed)")
		return
	}

	// Get the aggregator (current block proposer) address
	slot := n.blockProducer.GetCurrentSlot()
	_, aggregatorAddr := n.blockProducer.isProposerForSlot(slot)

	// Encrypt private data for the aggregator using one-shot Kyber768 KEM
	encrypted, err := n.keyExchange.SealForPeer(aggregatorAddr, privateData)
	if err != nil {
		nodeLog.Error("SECURITY: TSS sendPrivateRound2: encryption failed for aggregator %x: %v — private data NOT sent (fail-closed)",
			aggregatorAddr[:8], err)
		return
	}

	// Prepend sender address so the aggregator knows which peer encrypted the payload
	myAddr := n.blockProducer.ValidatorAddr()
	payload := make([]byte, 20+len(encrypted))
	copy(payload[:20], myAddr[:])
	copy(payload[20:], encrypted)

	// Send point-to-point to the aggregator (NOT broadcast)
	if err := n.p2pHost.SendTSSToValidator(aggregatorAddr, p2p.MsgTypeTSSRound2Private, payload); err != nil {
		nodeLog.Warn("TSS: send private Round2 to aggregator %x failed: %v", aggregatorAddr[:8], err)
	}
}

// handleTSSRound2Reveal processes the public part of a Round2 reveal.
// AUDIT (2026) TSS B-3: Verify sender ↔ participantID binding.
func (n *Node) handleTSSRound2Reveal(msg p2p.PeerMessage) {
	sessionID, reveal, err := tss.DecodeRound2RevealPublic(msg.Payload)
	if err != nil {
		nodeLog.Warn("TSS Round2 reveal decode error: %v", err)
		return
	}

	// AUDIT (2026) TSS B-3: Bind sender to participantID.
	senderAddr, found := n.resolveSenderAddress(msg.From)
	if !found {
		nodeLog.Warn("TSS Round2 reveal: cannot resolve sender address, rejecting (B-3)")
		return
	}
	if !n.validateSenderParticipantID(senderAddr, reveal.ParticipantID) {
		nodeLog.Warn("TSS Round2 reveal: sender %x does not match participantID %d, rejecting (B-3)",
			senderAddr[:8], reveal.ParticipantID)
		return
	}

	if err := n.distributedSigner.SubmitRound2Reveal(sessionID, reveal); err != nil {
		nodeLog.Warn("TSS Round2 reveal submit error: %v", err)
		return
	}

	nodeLog.Debug("TSS Round2 reveal received: session=%x, participant=%d",
		sessionID[:8], reveal.ParticipantID)
}

// handleTSSRound2Private processes the encrypted private part of a Round2 reveal.
//
// SECURITY (P0 fix): The payload must be encrypted. The first 20 bytes are the
// sender's validator address (in plaintext — this is public information), followed
// by the Kyber768 KEM + AES-256-GCM ciphertext. If decryption fails, the message
// is REJECTED — no plaintext fallback.
//
// AUDIT (2026) TSS-FIX (CRITICAL): The decoded payload now contains a
// SINGLE combined Z0Share (λ_i·c·(t0_i - s2_i)) instead of the previously
// separate Cs2Share (λ_i·c·s2_i) and Ct0Share (λ_i·c·t0_i). The old separate
// contributions allowed the aggregator to invert the challenge polynomial c in
// the NTT ring and recover s2 and t0 separately, then s1 via A·s1 = t - s2,
// reconstructing the FULL Dilithium3 private key. The new combined Z0Share
// cannot be decomposed by the aggregator (residual risk: s1 recovery only).
// The aggregator attaches it via AttachZ0Contribution. Raw s2_i/t0_i shares
// NEVER traverse the wire.
func (n *Node) handleTSSRound2Private(msg p2p.PeerMessage) {
	if n.keyExchange == nil {
		nodeLog.Warn("TSS Round2 private: keyExchange not available, rejecting encrypted share")
		return
	}

	// Payload format: senderAddr (20 bytes) + encrypted blob
	if len(msg.Payload) < 20 {
		nodeLog.Warn("TSS Round2 private: payload too small (need at least 20 bytes for sender address), rejecting")
		return
	}

	var senderAddr types.Address
	copy(senderAddr[:], msg.Payload[:20])

	plaintext, err := n.keyExchange.OpenFromPeer(senderAddr, msg.Payload[20:])
	if err != nil {
		nodeLog.Warn("TSS Round2 private: decrypt failed from sender %x, rejecting: %v", senderAddr[:8], err)
		return
	}

	// AUDIT (2026) TSS-FIX: New wire format carries a SINGLE
	// combined z0 contribution (z0Share) instead of separate cs2/ct0 shares.
	// TSS-FIX (2026-07-17): Also decodes the embedded freshness timestamp.
	sessionID, participantID, msgTimestamp, zShare, z0Share, err := tss.DecodeRound2RevealPrivate(plaintext)
	if err != nil {
		nodeLog.Warn("TSS Round2 private decode error: %v", err)
		return
	}

	// AUDIT (2026) TSS B-3: Verify senderAddr maps to the claimed
	// participantID. senderAddr was extracted from the payload above (the
	// first 20 bytes of the P2P message, set by the sender). Without this
	// check, any peer could claim any participantID and inject malicious
	// z0 contributions.
	if !n.validateSenderParticipantID(senderAddr, participantID) {
		nodeLog.Warn("TSS Round2 private: sender %x does not match participantID %d, rejecting (B-3)",
			senderAddr[:8], participantID)
		return
	}

	// AUDIT (2026) TSS B-4: Only accept shares for the current
	// aggregator session. Prevents cross-session share misdelivery where
	// z0 contributions from an old session are attached to a new one.
	if !n.isCurrentAggregatorSession(sessionID[:]) {
		nodeLog.Warn("TSS Round2 private: session %x is not the current aggregator session, rejecting (B-4)",
			sessionID[:8])
		return
	}

	// AUDIT (2026) TSS-FIX: Freshness window + per-(session,
	// participant) strict monotonic increase.
	//
	// B-3 (sender↔participantID) and B-4 (current session) prevent cross-
	// participant and cross-session misdelivery, but a malicious P2P relay
	// can still replay an identical ciphertext within the same session for
	// the same participant. The original design had no per-message nonce
	// or timestamp. We now require:
	//
	//   1. |now - msgTimestamp| <= round2PrivateFreshnessWindow (±5min)
	//      — bounds clock skew, rejects delayed replays from old sessions
	//        even when the aggregator session ID was reused.
	//   2. msgTimestamp > lastTS[sessionID||participantID]
	//      — strict monotonic increase within the session rejects identical
	//        or out-of-order replays. The first message for a key sets
	//        lastTS = msgTimestamp; subsequent messages must be strictly
	//        greater. The map is cleared when the session is cleaned.
	//
	// Failure mode: fail-CLOSED. Any freshness violation drops the message.
	if !n.validateRound2PrivateFreshness(sessionID, participantID, msgTimestamp) {
		return
	}

	// AUDIT (2026) TSS-FIX: Attach the combined z0 contribution
	// (not raw shares, and not separate cs2/ct0). AttachZ0Contribution stores
	// Z0Share on the reveal so Round2Aggregate can sum it directly. No raw
	// s2_i/t0_i ever enters the aggregator, and the aggregator cannot
	// decompose Z0Share into c·s2 and c·t0 separately.
	err = n.distributedSigner.AttachZ0Contribution(sessionID, participantID, z0Share, zShare)
	if err != nil {
		nodeLog.Warn("TSS Round2 private attach error: %v", err)
		return
	}

	nodeLog.Debug("TSS Round2 private share received: session=%x, participant=%d (z=%d, z0=%d bytes)",
		sessionID[:8], participantID, len(zShare), len(z0Share))
}

// handleTSSSignature processes a final aggregated signature broadcast.
func (n *Node) handleTSSSignature(msg p2p.PeerMessage) {
	sessionID, signature, err := tss.DecodeSignature(msg.Payload)
	if err != nil {
		nodeLog.Warn("TSS signature decode error: %v", err)
		return
	}

	nodeLog.Info("TSS final signature received: session=%x, sig_size=%d",
		sessionID[:8], len(signature))

	n.distributedSigner.CleanSession(sessionID)
}

// handleTSSKeyExchange processes a Kyber public key broadcast from another validator.
// AUDIT (2026) HIGH-06/CRND-06: The payload must include a Dilithium3
// signature over (addr || kyberPubKey). The signature is verified against the
// validator's consensus Dilithium public key from the validator set. Messages
// without a valid signature are rejected, preventing unauthorized key replacement.
func (n *Node) handleTSSKeyExchange(msg p2p.PeerMessage) {
	// SYNC-TSS-01 FIX (deep-audit 2026-07-12): the header is 24 bytes
	// (Address[20] + Timestamp[8] + KyberPubKeyLen[4]); the length prefix is
	// read from Payload[28..31] below. The old `< 24` guard (for the
	// pre-CRND-01 format without timestamp) let a 20-23 byte payload pass and
	// then index out of range — a peer-triggerable panic (no recover in the
	// TSS loop) that crashes any node with distributed TSS enabled.
	//
	// AUDIT (2026) CRND-01 FIX: Payload format now includes an 8-byte
	// big-endian Unix timestamp between Address and KyberPubKeyLen. The
	// timestamp is part of the signed message, so it cannot be forged.
	if n.keyExchange == nil || len(msg.Payload) < 32 {
		return
	}

	// Format: Address(20) + Timestamp(8) + KyberPubKeyLen(4) + KyberPubKey + SigLen(4) + Sig
	addr := make([]byte, 20)
	copy(addr, msg.Payload[:20])
	timestamp := int64(binary.BigEndian.Uint64(msg.Payload[20:28]))
	kyberLen := int(msg.Payload[28])<<24 | int(msg.Payload[29])<<16 | int(msg.Payload[30])<<8 | int(msg.Payload[31])
	// Reject absurd/negative-looking lengths early. A Kyber768 public key is
	// 1184 bytes; cap generously to bound allocation before the exact check.
	if kyberLen <= 0 || kyberLen > 1<<20 {
		nodeLog.Warn("TSS key exchange: invalid key length")
		return
	}
	if len(msg.Payload) < 32+kyberLen {
		nodeLog.Warn("TSS key exchange: invalid payload size")
		return
	}

	kyberPubKey := msg.Payload[32 : 32+kyberLen]
	var validatorAddr types.Address
	copy(validatorAddr[:], addr)

	// AUDIT (2026) CRND-01: Reject stale or replayed broadcasts before
	// doing the expensive signature verification. This prevents an attacker
	// from replaying a captured signed broadcast to downgrade a validator's
	// legitimately rotated Kyber key.
	if err := n.keyExchange.CheckKyberBroadcastFreshness(validatorAddr, timestamp); err != nil {
		nodeLog.Warn("TSS key exchange: rejected replayed/stale broadcast from %x: %v (CRND-01)", validatorAddr[:8], err)
		return
	}

	// AUDIT (2026) HIGH-06/CRND-06: Extract and verify Dilithium3 signature.
	// The signature must cover addr || timestamp || kyberPubKey and be verified
	// against the validator's consensus Dilithium public key. This prevents an
	// attacker from replacing another validator's Kyber key. The timestamp
	// (CRND-01) prevents replay of a captured valid signature.
	sigOff := 32 + kyberLen
	if len(msg.Payload) < sigOff+4 {
		nodeLog.Warn("TSS key exchange: rejected — no signature (HIGH-06 fix)")
		return
	}
	sigLen := int(msg.Payload[sigOff])<<24 | int(msg.Payload[sigOff+1])<<16 | int(msg.Payload[sigOff+2])<<8 | int(msg.Payload[sigOff+3])
	if sigLen <= 0 || sigLen > 1<<16 {
		nodeLog.Warn("TSS key exchange: invalid signature length")
		return
	}
	if len(msg.Payload) < sigOff+4+sigLen {
		nodeLog.Warn("TSS key exchange: payload too short for signature")
		return
	}
	signature := msg.Payload[sigOff+4 : sigOff+4+sigLen]

	// Verify the validator is known and active, then verify the signature.
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		nodeLog.Warn("SECURITY: TSS key exchange: validator set unavailable — rejecting Kyber key from %x (HIGH-06: fail-closed)", validatorAddr[:8])
		return
	}
	vs := n.blockProducer.QPOS().GetValidatorSet()
	if vs == nil {
		nodeLog.Warn("SECURITY: TSS key exchange: validator set not initialized — rejecting Kyber key from %x (HIGH-06: fail-closed)", validatorAddr[:8])
		return
	}
	v := vs.GetValidator(validatorAddr)
	if v == nil || !v.Active {
		nodeLog.Warn("TSS key exchange: rejected Kyber key from unknown/inactive validator %x", validatorAddr[:8])
		return
	}
	if len(v.PublicKeyBytes) == 0 {
		nodeLog.Warn("TSS key exchange: validator %x has no consensus public key — rejecting", validatorAddr[:8])
		return
	}
	pubKey, err := crypto.PublicKeyFromBytes(v.PublicKeyBytes)
	if err != nil {
		nodeLog.Warn("TSS key exchange: invalid consensus public key for %x: %v", validatorAddr[:8], err)
		return
	}
	// CRND-01: signature covers addr || timestamp || kyberPubKey
	sigMsg := make([]byte, 20+8+len(kyberPubKey))
	copy(sigMsg[:20], addr)
	binary.BigEndian.PutUint64(sigMsg[20:28], uint64(timestamp))
	copy(sigMsg[28:], kyberPubKey)
	if !crypto.Verify(pubKey, sigMsg, signature) {
		nodeLog.Warn("TSS key exchange: Dilithium signature verification FAILED for validator %x — rejecting (HIGH-06)", validatorAddr[:8])
		return
	}

	// AUDIT (2026) CRND-FIX: Commit the freshness high-water mark
	// ONLY after signature verification succeeds. Previously, the check
	// function wrote the timestamp before verification, so a forged broadcast
	// with a future timestamp would block the legitimate validator's
	// subsequent broadcast as "out-of-order".
	n.keyExchange.CommitKyberBroadcastFreshness(validatorAddr, timestamp)

	if err := n.keyExchange.RegisterKyberKey(validatorAddr, kyberPubKey); err != nil {
		if errors.Is(err, consensus.ErrKyberKeyAlreadyExists) {
			// Signature verified — legitimate key rotation.
			nodeLog.Info("TSS key exchange: accepting Kyber key rotation for validator %x (signature verified)", validatorAddr[:8])
			if replaceErr := n.keyExchange.ForceReplaceKyberKey(validatorAddr, kyberPubKey); replaceErr != nil {
				nodeLog.Warn("TSS key exchange: force replace Kyber key failed: %v", replaceErr)
				return
			}
		} else {
			nodeLog.Warn("TSS key exchange: register Kyber key failed: %v", err)
			return
		}
	}

	// Initiate encrypted session with this peer
	if _, err := n.keyExchange.InitiateSession(validatorAddr); err != nil {
		nodeLog.Debug("TSS key exchange: initiate session with %x failed: %v", validatorAddr[:8], err)
	}

	nodeLog.Info("TSS key exchange: registered Kyber key for validator %x (signature verified)", validatorAddr[:8])
}

// broadcastKyberPublicKey broadcasts this node's Kyber public key to all peers.
// AUDIT (2026) HIGH-06/CRND-06: The payload now includes a Dilithium3
// signature over (addr || timestamp || kyberPubKey) to authenticate the sender.
// Receivers verify this signature against the validator's consensus Dilithium
// public key, preventing unauthorized key replacement attacks.
//
// AUDIT (2026) CRND-01 FIX: A Unix timestamp (8 bytes, big-endian) is now
// included in both the payload and the signed message. Receivers reject
// broadcasts whose timestamp is outside ±5 minutes of local time or older
// than the last timestamp seen from the same validator. This prevents replay
// attacks where a captured signed broadcast is retransmitted later to
// overwrite a legitimately rotated key (downgrade attack).
func (n *Node) broadcastKyberPublicKey() {
	if n.keyExchange == nil || n.blockProducer == nil {
		return
	}

	pubKey, err := n.keyExchange.LocalKyberPublicKey()
	if err != nil {
		nodeLog.Warn("TSS: failed to get local Kyber public key: %v", err)
		return
	}

	addr := n.blockProducer.ValidatorAddr()

	// AUDIT (2026) HIGH-06/CRND-01: Sign addr||timestamp||kyberPubKey with Dilithium3 key
	vk := n.blockProducer.ValidatorKey()
	if vk == nil {
		nodeLog.Warn("TSS: cannot sign Kyber key exchange: validator key not configured")
		return
	}
	timestamp := time.Now().Unix()
	sigMsg := make([]byte, 20+8+len(pubKey))
	copy(sigMsg[:20], addr[:])
	binary.BigEndian.PutUint64(sigMsg[20:28], uint64(timestamp))
	copy(sigMsg[28:], pubKey)
	sig, err := vk.Sign(sigMsg)
	if err != nil {
		nodeLog.Warn("TSS: failed to sign Kyber key exchange: %v", err)
		return
	}

	// Format: Address(20) + Timestamp(8) + KyberPubKeyLen(4) + KyberPubKey + SigLen(4) + Sig
	payload := make([]byte, 32+len(pubKey)+4+len(sig))
	copy(payload[:20], addr[:])
	binary.BigEndian.PutUint64(payload[20:28], uint64(timestamp))
	payload[28] = byte(len(pubKey) >> 24)
	payload[29] = byte(len(pubKey) >> 16)
	payload[30] = byte(len(pubKey) >> 8)
	payload[31] = byte(len(pubKey))
	copy(payload[32:32+len(pubKey)], pubKey)
	sigOff := 32 + len(pubKey)
	payload[sigOff] = byte(len(sig) >> 24)
	payload[sigOff+1] = byte(len(sig) >> 16)
	payload[sigOff+2] = byte(len(sig) >> 8)
	payload[sigOff+3] = byte(len(sig))
	copy(payload[sigOff+4:], sig)

	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSKeyExchange, payload); err != nil {
		nodeLog.Warn("TSS: broadcast Kyber public key failed: %v", err)
	}

	// Also register our own Kyber key locally (for self-encryption in local mode)
	if err := n.keyExchange.RegisterKyberKey(addr, pubKey); err != nil {
		nodeLog.Warn("TSS: register own Kyber key locally failed: %v", err)
	}

	nodeLog.Info("TSS: Kyber public key broadcast (size=%d, ts=%d)", len(pubKey), timestamp)
}

// wireTSSDistributed connects the distributed signer to the P2P layer.
func (n *Node) wireTSSDistributed() {
	if n.distributedSigner == nil || n.p2pHost == nil {
		return
	}

	// Broadcast our Kyber public key so other nodes can encrypt to us
	n.broadcastKyberPublicKey()

	nodeLog.Info("TSS distributed signer wired to P2P layer")
}

// tssCanonicalMessageForCurrentSlot derives the canonical 32-byte message
// that distributed TSS must sign for the given originalMessage at the
// current chain state. R38-P1-03 FIX.
//
// All SignBlock/AggregatePartialSignatures callers sign block-related
// messages, so we use the tssDomainTagBlock. SignVote callers are routed
// through the same distributeTSSSign path today — should SignVote ever
// require a different domain tag, the ThresholdKeySigner interface would
// need an extension (out of surgical P1 scope; the kill-switch is off
// by default, so this is defense-in-depth when an operator opens it).
//
// Fail-closed: when the local block producer is nil or the slot/proposer
// cannot be determined, returns a SHA-256 of the originalMessage alone —
// this will NOT match the participants' re-derived canonical (which
// uses real chain context), so the session will reject at the binding
// check rather than sign an out-of-context message. This is the safe
// failure mode (no oracle activity).
func (n *Node) tssCanonicalMessageForCurrentSlot(originalMessage []byte) []byte {
	if n.blockProducer == nil {
		h := sha256.Sum256(originalMessage)
		return h[:]
	}
	slot := n.blockProducer.GetCurrentSlot()
	_, proposerAddr := n.blockProducer.isProposerForSlot(slot)
	chainID := n.chainID
	if chainID == 0 {
		// R38-P1-03: hard-code the mainnet default to mirror the
		// rpc/multisig_api.go attempt at consistency. This is a
		// last-resort fallback; in production n.chainID is populated
		// from genesis at startup (see node.go initConsensus path).
		chainID = 1668
	}
	epoch := slot / consensus.SlotsPerEpoch
	out := computeTSSCanonicalBinding(chainID, epoch, slot, proposerAddr, tssDomainTagBlock, originalMessage)
	return out[:]
}

// encodeBoundSessionInit wraps the canonical message + the R38-P1-03 binding
// tail into a single SessionInit payload suitable for BroadcastTSS. R38-P1-03 FIX.
func (n *Node) encodeBoundSessionInit(sessionID [32]byte, canonicalMessage []byte, participantIDs []int, originalMessage []byte) []byte {
	slot := uint64(0)
	var proposer types.Address
	if n.blockProducer != nil {
		slot = n.blockProducer.GetCurrentSlot()
		_, proposer = n.blockProducer.isProposerForSlot(slot)
	}
	chainID := n.chainID
	if chainID == 0 {
		chainID = 1668
	}
	epoch := slot / consensus.SlotsPerEpoch
	return encodeTSSSessionInitBound(
		sessionID, canonicalMessage, participantIDs,
		time.Now().UnixNano(),
		chainID, epoch, slot, proposer,
		tssDomainTagBlock, originalMessage,
	)
}

// DistributeTSSSign is called by the consensus layer (via tssSignerAdapter)
// when a distributed threshold signature is needed. The aggregator:
//  1. Creates a signing session
//  2. Broadcasts session init to all participants
//  3. Computes and broadcasts its own Round1 commitment + W_i
//  4. Waits for all Round1 commitments (participants send their own)
//  5. Computes its own Round2 reveal
//  6. Waits for threshold Round2 reveals from participants
//  7. Aggregates the final signature
//  8. Broadcasts the final signature
//
// allowFallback=true permits falling back to local SignWithRetry on distributed
// signing failure (used by SignBlock/SignVote for liveness).
// allowFallback=false enforces strict distributed signing (used by
// AggregatePartialSignatures to preserve t-of-n threshold security).
func (n *Node) DistributeTSSSign(message []byte, participantIDs []int) ([]byte, error) {
	return n.distributeTSSSign(message, participantIDs, true)
}

// distributeTSSSignNoFallback performs distributed TSS signing without
// falling back to local SignWithRetry. Used by AggregatePartialSignatures
// to enforce strict threshold security.
func (n *Node) distributeTSSSignNoFallback(message []byte, participantIDs []int) ([]byte, error) {
	return n.distributeTSSSign(message, participantIDs, false)
}

func (n *Node) distributeTSSSign(message []byte, participantIDs []int, allowFallback bool) ([]byte, error) {
	// fallbackToLocal returns a local SignWithRetry result if allowed,
	// otherwise returns an error. Used to centralize the fallback decision.
	fallbackToLocal := func(reason string, origErr error) ([]byte, error) {
		if allowFallback {
			nodeLog.Warn("DistributeTSSSign: %s: %v, falling back to local", reason, origErr)
			return n.tssManager.SignWithRetry(message, participantIDs)
		}
		return nil, fmt.Errorf("distributed TSS failed: %s: %w (no fallback to local)", reason, origErr)
	}

	if n.distributedSigner == nil {
		return fallbackToLocal("nil distributed signer", fmt.Errorf("distributed signer not initialized"))
	}

	// TSS-R9-CRIT-01 FIX: resolve myParticipantID BEFORE InitiateSession
	// so we can pass it to the new CreateParticipantSession-based path.
	// The aggregator's local QTD session now loads ONLY this node's own
	// share (preserving t-of-n threshold security) instead of all shares.
	myPID := n.getMyParticipantID()
	if myPID < 0 {
		return fallbackToLocal("cannot determine participant ID", fmt.Errorf("getMyParticipantID returned -1"))
	}

	// R38-P1-03 FIX: Replace the caller-supplied raw message with its
	// canonical binding — a SHA-256 envelope that also includes chainID,
	// epoch, slot, proposer, domainTag. This guarantees that EVERY signature
	// produced by distributed TSS is bound to one specific (chain, epoch,
	// slot, proposer, domain) tuple, eliminating the arbitrary-message
	// oracle attack described in R38-P1-03. Verification paths on the
	// receiving side re-derive this envelope and verify equality.
	//
	// domainTag selection: SignBlock callers sign block-header-derived
	// hashes ("block"); AggregatePartialSignatures callers also sign block
	// sealing messages ("block"). SignVote callers sign consensus votes
	// ("vote"). The dispatcher below defaults to "block" because every
	// call into distributeTSSSign today goes through SignBlock or the
	// seal (AggregatePartialSignatures) path; a future SignVote wiring
	// would pass allowFallback=false + a "vote" tag, which would require
	// extending the ThresholdKeySigner interface (out of scope for this
	// surgical P1 fix — the kill-switch is off by default, so this is a
	// defense-in-depth guard for when the operator opens it intentionally).
	//
	// Participants re-derive the canonical envelope from the binding tail
	// and reject any mismatch — see handleTSSSessionInit.
	canonicalMessage := n.tssCanonicalMessageForCurrentSlot(message)
	// Step 1: Initiate session
	sessionID, err := n.distributedSigner.InitiateSession(canonicalMessage, participantIDs, myPID)
	if err != nil {
		return fallbackToLocal("initiate session", err)
	}
	// AUDIT (2026) TSS B-4: Track the current aggregator session so
	// that incoming private shares can be validated against it. The defer
	// guarantees the session is cleared on EVERY exit path (success, error,
	// fallback), preventing cross-session share misdelivery.
	n.setAggregatorSession(sessionID[:])
	defer n.clearAggregatorSession()

	// Step 2: Broadcast session init
	// TSS-M8 (R8 2026-07-19 FIX): Attach the aggregator's authoritative
	// Unix-nano timestamp so participants can compute their session timeout
	// from the aggregator's wall-clock rather than their own (which may be
	// skewed by NTP drift). Authenticated by the B-5 proposer check on the
	// receiving side, so a non-proposer cannot forge a different timestamp.
	//
	// R38-P1-03 FIX: Use the bound payload (legacy SessionInit + canonical
	// binding tail) so participants can re-derive and verify the canonical
	// envelope on receipt.
	boundInitData := n.encodeBoundSessionInit(sessionID, canonicalMessage, participantIDs, message)
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSSessionInit, boundInitData); err != nil {
		nodeLog.Warn("DistributeTSSSign: broadcast session init failed: %v", err)
	}

	// Step 3: Compute and broadcast OWN Round1 commitment + W_i only.
	// myPID was already resolved above (before InitiateSession) for the
	// TSS-R9-CRIT-01 fix; reuse it instead of recomputing.
	commitment, wBytes, err := n.distributedSigner.ComputeRound1Commitment(sessionID, myPID)
	if err != nil {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("compute Round1", err)
	}

	// Submit own commitment + W locally
	n.distributedSigner.SubmitRound1Commitment(sessionID, commitment)
	n.distributedSigner.SubmitRound1W(sessionID, myPID, wBytes)

	// Broadcast Round1 commitment + W_i to all participants
	commitData, err := tss.EncodeRound1Commitment(sessionID, commitment, wBytes)
	if err != nil {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("encode Round1 commit", err)
	}
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSRound1Commit, commitData); err != nil {
		nodeLog.Warn("DistributeTSSSign: broadcast Round1 commit failed: %v", err)
	}

	// Step 4: Wait for Round1 to complete (participants send their commitments)
	if !n.waitForRound1(sessionID, 10*time.Second) {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("Round1 timeout", fmt.Errorf("did not receive all Round1 commitments within 10s"))
	}

	// Step 5: Compute own Round2 reveal
	reveal, err := n.distributedSigner.ComputeRound2Reveal(sessionID, myPID)
	if err != nil {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("compute Round2", err)
	}

	// Submit own reveal locally (public part)
	n.distributedSigner.SubmitRound2Reveal(sessionID, reveal)

	// Broadcast own public Round2 reveal
	revealData := tss.EncodeRound2RevealPublic(sessionID, reveal)
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSRound2Reveal, revealData); err != nil {
		nodeLog.Warn("DistributeTSSSign: broadcast Round2 reveal failed: %v", err)
	}

	// Process own private part locally (self-encrypt → self-decrypt)
	n.processOwnPrivateRound2(sessionID, myPID, reveal)

	// Step 6: Wait for Round2 to complete (participants send their reveals)
	if !n.waitForRound2(sessionID, 10*time.Second) {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("Round2 timeout", fmt.Errorf("did not receive all Round2 reveals within 10s"))
	}

	// Step 7: Aggregate the final signature
	signature, err := n.distributedSigner.AggregateSignature(sessionID)
	if err != nil {
		n.distributedSigner.CleanSession(sessionID)
		return fallbackToLocal("aggregate", err)
	}

	// Step 8: Broadcast the final signature
	sigData := tss.EncodeSignature(sessionID, signature)
	if err := n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSSignature, sigData); err != nil {
		nodeLog.Warn("DistributeTSSSign: broadcast signature failed: %v", err)
	}

	n.distributedSigner.CleanSession(sessionID)
	// AUDIT (2026) TSS B-4: aggregator session is cleared by the defer
	// declared after setAggregatorSession — no explicit call needed here.

	nodeLog.Info("DistributeTSSSign: success (sig_size=%d)", len(signature))
	return signature, nil
}

// processOwnPrivateRound2 handles the aggregator's own private Round2 data.
// The aggregator encrypts to itself and decrypts locally to exercise the same
// encryption path as distributed participants.
//
// AUDIT (2026) TSS-FIX (CRITICAL): The aggregator's own combined z0
// contribution (Z0Share) flows through the same encryption + decryption path as
// distributed participants. Raw S2/T0 shares are NEVER accessed here — the
// combined z0 contribution was already computed inside Round2Reveal(). The
// previous design transmitted separate Cs2Share/Ct0Share which allowed the
// aggregator to recover the full private key via NTT inversion; the new combined
// Z0Share cannot be decomposed (residual risk: s1 recovery only).
func (n *Node) processOwnPrivateRound2(sessionID [32]byte, pid int, reveal *qtd.Round2Reveal) {
	// AUDIT (2026) TSS-FIX: Encode the combined Z0Share directly
	// from the reveal. No raw S2/T0 share fetch — they never leave the node.
	// TSS-FIX (2026-07-17): Same freshness timestamp as sendPrivateRound2.
	privateData, err := tss.EncodeRound2RevealPrivate(sessionID, pid, time.Now().UnixNano(), reveal.ZShare, reveal.Z0Share)
	if err != nil {
		nodeLog.Error("SECURITY: processOwnPrivateRound2: encode private reveal failed for pid=%d: %v — private data NOT processed (fail-closed)", pid, err)
		return
	}

	if n.keyExchange == nil || n.blockProducer == nil {
		nodeLog.Warn("processOwnPrivateRound2: keyExchange or blockProducer is nil, cannot process private Round2")
		return
	}

	myAddr := n.blockProducer.ValidatorAddr()

	// Encrypt to self using one-shot Kyber768 KEM (same path as distributed participants)
	encrypted, err := n.keyExchange.SealForPeer(myAddr, privateData)
	if err != nil {
		nodeLog.Error("SECURITY: processOwnPrivateRound2: self-encryption failed: %v — private data NOT processed (fail-closed)", err)
		return
	}

	// Prepend sender address (self) and process locally via the same decryption path
	payload := make([]byte, 20+len(encrypted))
	copy(payload[:20], myAddr[:])
	copy(payload[20:], encrypted)

	// Process locally (decrypt + attach)
	n.handleTSSRound2Private(p2p.PeerMessage{
		Type:    p2p.MsgTypeTSSRound2Private,
		Payload: payload,
	})
}

// waitForRound1 polls until Round1 is complete or timeout.
func (n *Node) waitForRound1(sessionID [32]byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.distributedSigner.IsRound1Complete(sessionID) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// waitForRound2 polls until Round2 is complete or timeout.
func (n *Node) waitForRound2(sessionID [32]byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.distributedSigner.IsRound2Complete(sessionID) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// Quantaureum Node source, version 1.0.0.
// Package node provides the main node implementation for Quantaureum.
package node

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
)

// ============================================================================
// NODE-R12-H01 (2026-07-20) FIX: QTD seal concurrency & per-peer rate limit
//
// Audit finding (HIGH-14): BroadcastQTDSealRequest / BroadcastQTDPartialSeal
// had no concurrency or per-peer rate limiting. Dilithium3 aggregate signing
// is expensive (~50-200ms per attempt), so:
//   (a) On the OUTBOUND side: requestQTDSeal spawns a goroutine per call
//       (computeAndCompleteQTDSeal). Without a bound, a burst of slots
//       could spawn unbounded goroutines and exhaust CPU.
//   (b) On the INBOUND side: a malicious peer could spam
//       MsgTypeQTDSealRequest / MsgTypeQTDPartialSeal messages, each
//       triggering expensive Dilithium3 verification in
//       qfs.SubmitPartialSeal.
//
// Fix: (1) Counting semaphore on outbound (MaxConcurrentQTDSeals=3),
// acquired in computeAndCompleteQTDSeal with a short timeout — goroutines
// that cannot acquire exit early and the slot tick retries on the next
// iteration. (2) Per-peer sliding-window rate limit on inbound
// (qtdSealPerPeerMax messages per qtdSealPerPeerWindow), enforced in
// handleQTDSealRequest / handleQTDPartialSeal before any expensive work.
// ============================================================================

const (
	// MaxConcurrentQTDSeals bounds the number of computeAndCompleteQTDSeal
	// goroutines that may run in parallel. Each goroutine performs
	// Dilithium3 aggregate signing (up to ~200ms in distributed mode) plus
	// up to 3 retries with exponential backoff. Setting this to 3 means at
	// most 3 slots are being sealed concurrently — enough to keep up with
	// the 12-second slot tick even under retries, while preventing CPU
	// exhaustion from a burst of slot seal requests.
	MaxConcurrentQTDSeals = 3

	// qtdSealAcquireTimeout is how long a goroutine waits to acquire the
	// semaphore before giving up. The slot tick will retry on the next
	// iteration if this goroutine exits. A short timeout prevents the
	// goroutine from blocking indefinitely.
	qtdSealAcquireTimeout = 2 * time.Second

	// qtdSealPerPeerWindow is the sliding window for per-peer rate limiting
	// of inbound QTD seal messages. A peer may send at most
	// qtdSealPerPeerMax messages per window.
	qtdSealPerPeerWindow = 10 * time.Second

	// qtdSealPerPeerMax is the maximum number of QTD seal messages
	// (MsgTypeQTDSealRequest + MsgTypeQTDPartialSeal combined) that a
	// single peer may send per qtdSealPerPeerWindow. A typical executive
	// chamber has 7-11 members; each member sends at most 1 partial seal
	// per slot, and the proposer sends 1 seal request per slot. With a
	// 12-second slot tick and a 10-second window, an honest proposer sends
	// at most ~1 seal request per window, and each executive member sends
	// at most ~1 partial seal per window. A limit of 20 is generous for
	// honest peers but blocks flood attacks (which send hundreds).
	qtdSealPerPeerMax = 20

	// qtdPeerRateMaxSize caps the number of peers tracked in the
	// qtdPeerRate map. Without this cap, the map grows unbounded on
	// long-running nodes as peers join and leave the network, each
	// leaving a ~40-byte qtdPeerRateInfo entry behind. At ~40 bytes per
	// entry, 1M peers would consume ~40MB — not catastrophic, but
	// pointless when entries older than qtdPeerRateTTL serve no purpose.
	// 1024 is generous for a Quantaureum validator network (the executive
	// chamber has 7-11 members per epoch, and even with peer churn the
	// number of distinct peers sending QTD seal messages in a 1-hour TTL
	// window is well under 1024).
	// P2P-R15-CRIT-003 (2026-07-22).
	qtdPeerRateMaxSize = 1024

	// qtdPeerRateTTL is the time-to-live for entries in the qtdPeerRate
	// map. Entries whose lastSeen is older than this TTL are eligible for
	// cleanup. 1 hour is generous — an honest peer sends at most ~1 QTD
	// seal message per 12-second slot, so any peer that hasn't been seen
	// in an hour is likely disconnected and its rate-limit state is stale.
	// P2P-R15-CRIT-003 (2026-07-22).
	qtdPeerRateTTL = time.Hour
)

// qtdPeerRateInfo tracks per-peer rate-limit state for QTD seal messages.
//
// Layout:
//   - windowStart: when the current window began (reset if older than
//     qtdSealPerPeerWindow)
//   - count: number of messages accepted in the current window
//   - lastSeen: when this peer was last seen (updated on every
//     allowQTDSealFromPeer call). Used by CleanupQTDPeerRate to prune
//     stale entries. P2P-R15-CRIT-003 (2026-07-22).
//
// All access MUST be guarded by Node.qtdPeerRtMu.
type qtdPeerRateInfo struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

// ensureQTDSealLimiter lazily initializes the QTD seal limiter fields.
//
// Production code paths go through NewNode which eagerly initializes these
// fields, but many tests construct &Node{} directly without NewNode. This
// helper lets those tests use the rate-limit / semaphore code paths safely
// without crashing.
//
// Called from the inbound handlers and from computeAndCompleteQTDSeal; the
// mutex serializes initialization so concurrent callers see the same state.
func (n *Node) ensureQTDSealLimiter() {
	n.qtdPeerRtMu.Lock()
	defer n.qtdPeerRtMu.Unlock()
	if n.qtdSealSem == nil {
		n.qtdSealSem = make(chan struct{}, MaxConcurrentQTDSeals)
	}
	if n.qtdPeerRate == nil {
		n.qtdPeerRate = make(map[p2p.PeerID]*qtdPeerRateInfo)
	}
}

// allowQTDSealFromPeer returns true if the peer may send another QTD seal
// message within the per-peer rate limit, false otherwise.
//
// Sliding window: a counter resets when the current window (qtdSealPerPeerWindow)
// elapses. Once the counter exceeds qtdSealPerPeerMax within a window, all
// subsequent messages from that peer are rejected until the window resets.
//
// This is a defense-in-depth control on top of B-3 (sender matches
// validatorIndex) and B-5 (sender is the slot proposer). A misconfigured or
// compromised authenticated peer could otherwise flood the inbound path and
// cause CPU exhaustion through qfs.SubmitPartialSeal.
//
// P2P-R15-CRIT-003 (2026-07-22): The qtdPeerRate map is bounded by
// qtdPeerRateMaxSize. When the map reaches this size, stale entries
// (lastSeen older than qtdPeerRateTTL) are pruned before adding a new peer.
// lastSeen is updated on every call so active peers are never pruned.
func (n *Node) allowQTDSealFromPeer(peerID p2p.PeerID) bool {
	n.ensureQTDSealLimiter()
	now := time.Now()
	n.qtdPeerRtMu.Lock()
	defer n.qtdPeerRtMu.Unlock()

	// P2P-R15-CRIT-003: If the map has reached maxSize, clean up stale
	// entries first to make room for the new peer. This bounds the map
	// size and prevents unbounded memory growth on long-running nodes.
	// The cleanup is inlined (rather than calling CleanupQTDPeerRate) to
	// avoid re-acquiring qtdPeerRtMu (which would deadlock).
	if len(n.qtdPeerRate) >= qtdPeerRateMaxSize {
		for pid, info := range n.qtdPeerRate {
			if now.Sub(info.lastSeen) >= qtdPeerRateTTL {
				delete(n.qtdPeerRate, pid)
			}
		}
	}

	info, ok := n.qtdPeerRate[peerID]
	if !ok || now.Sub(info.windowStart) >= qtdSealPerPeerWindow {
		info = &qtdPeerRateInfo{windowStart: now, count: 0}
		n.qtdPeerRate[peerID] = info
	}
	info.count++
	info.lastSeen = now // P2P-R15-CRIT-003: update lastSeen on every access
	return info.count <= qtdSealPerPeerMax
}

// acquireQTDSealSlot attempts to acquire a slot in the QTD seal concurrency
// semaphore within qtdSealAcquireTimeout. Returns true if acquired (caller
// MUST call releaseQTDSealSlot when done), false if the timeout elapsed
// (caller should exit early).
//
// The semaphore is a buffered channel of size MaxConcurrentQTDSeals. Send
// blocks when the buffer is full; receiving releases a slot. The context-
// aware select lets us give up after qtdSealAcquireTimeout so the goroutine
// doesn't block indefinitely if all slots are held by long-running retries.
func (n *Node) acquireQTDSealSlot() bool {
	n.ensureQTDSealLimiter()
	timer := time.NewTimer(qtdSealAcquireTimeout)
	defer timer.Stop()
	select {
	case n.qtdSealSem <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// releaseQTDSealSlot releases a slot in the QTD seal concurrency semaphore.
// MUST be called exactly once for each successful acquireQTDSealSlot.
// Safe to call from a defer; using defer right after acquire is the
// recommended pattern.
func (n *Node) releaseQTDSealSlot() {
	n.qtdPeerRtMu.Lock()
	sem := n.qtdSealSem
	n.qtdPeerRtMu.Unlock()
	if sem == nil {
		return
	}
	select {
	case <-sem:
	default:
		// Should never happen if acquire/release are paired; log and move on.
		nodeLog.Warn("NODE-R12-H01: releaseQTDSealSlot called without matching acquire (semaphore underflow)")
	}
}

// GetQTDSealSemaphoreFill returns the current number of in-flight
// computeAndCompleteQTDSeal goroutines (for observability/metrics).
func (n *Node) GetQTDSealSemaphoreFill() int {
	n.qtdPeerRtMu.Lock()
	sem := n.qtdSealSem
	n.qtdPeerRtMu.Unlock()
	if sem == nil {
		return 0
	}
	return len(sem)
}

// GetQTDPeerRateCount returns the number of peers currently tracked by the
// per-peer rate limiter (for observability/metrics).
func (n *Node) GetQTDPeerRateCount() int {
	if n.qtdPeerRate == nil {
		return 0
	}
	n.qtdPeerRtMu.Lock()
	defer n.qtdPeerRtMu.Unlock()
	return len(n.qtdPeerRate)
}

// CleanupQTDPeerRate removes stale entries from the qtdPeerRate map.
// Entries are considered stale if their lastSeen is older than qtdPeerRateTTL.
// Returns the number of entries removed.
// P2P-R15-CRIT-003 (2026-07-22).
func (n *Node) CleanupQTDPeerRate() int {
	n.ensureQTDSealLimiter()
	now := time.Now()
	n.qtdPeerRtMu.Lock()
	defer n.qtdPeerRtMu.Unlock()

	removed := 0
	for pid, info := range n.qtdPeerRate {
		if now.Sub(info.lastSeen) >= qtdPeerRateTTL {
			delete(n.qtdPeerRate, pid)
			removed++
		}
	}
	return removed
}

// qtdSealProcessingLoop processes incoming QTD partial seal messages from peers.
// P1-4/P1-5: This is the P2P bridge for executive chamber seal collection.
//
// Message format (MsgTypeQTDPartialSeal):
//
//	[0:8]   uint64 slot
//	[8:16]  uint64 validatorIndex
//	[16:20] uint32 sigLen
//	[20:20+sigLen] partial seal signature
//
// Message format (MsgTypeQTDSealRequest):
//
//	[0:8]   uint64 slot
//	[8:40]  types.Hash blockHash
func (n *Node) qtdSealProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// QTD seal decoding or aggregation cannot kill this goroutine and
	// stall instant-finality propagation.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("qtdSealProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	if n.p2pHost == nil {
		return
	}

	qtdCh := n.p2pHost.SubscribeQTDSeal()
	for {
		select {
		case <-n.ctx.Done():
			return
		case msg := <-qtdCh:
			// Per-message recover: a malformed QTD seal message must not
			// terminate the loop.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("qtdSealProcessingLoop: message panic recovered: %v", r)
					}
				}()
				n.handleQTDSealMessage(msg)
			}()
		}
	}
}

// handleQTDSealMessage dispatches QTD seal messages by type.
func (n *Node) handleQTDSealMessage(msg p2p.PeerMessage) {
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}

	switch msg.Type {
	case p2p.MsgTypeQTDSealRequest:
		n.handleQTDSealRequest(msg)
	case p2p.MsgTypeQTDPartialSeal:
		n.handleQTDPartialSeal(msg)
	}
}

// handleQTDSealRequest processes a seal request from the block producer.
//
// R7 P0-1 FIX (2026-07-17): Previously, each executive chamber member
// independently signed the block hash with validatorKey.Sign (single-signer
// Dilithium3) and broadcast it as a "partial seal". This completely bypassed
// the QTD threshold signature protocol — the resulting signatures were
// either rejected by AggregatePartialSignatures (local mode) or ignored
// (distributed mode).
//
// New behavior: The seal request is now a NOTIFICATION only. Executive
// members validate it (B-5 + R4-CORE-04) but do NOT produce partial sigs.
// The proposer computes the full QTD threshold signature asynchronously via
// qfs.AggregateAndCompleteSeal (which routes to distributeTSSSignNoFallback
// in distributed mode, or SignWithRetry in local mode).
//
// QUANTUM-FIX (B-5): Verify the sender is the current slot proposer.
// Without this, any peer could broadcast a seal request and trick executive
// members into computing signatures for arbitrary block hashes.
//
// QUANTUM-FIX (R4-CORE-04): Verify blockHash matches the canonical
// chain root for the slot. Without this, a malicious proposer could request
// seals for non-canonical fork blocks.
//
// NODE-R12-H01 FIX (2026-07-20): Per-peer rate limit. A compromised or
// misconfigured proposer could otherwise flood the inbound path with
// MsgTypeQTDSealRequest messages, each triggering the proposer-check +
// canonical-root-check + chamber lookups. The rate limit caps this at
// qtdSealPerPeerMax per qtdSealPerPeerWindow per peer.
func (n *Node) handleQTDSealRequest(msg p2p.PeerMessage) {
	// NODE-R12-H01: Per-peer rate limit. Enforced BEFORE any expensive
	// work (proposer lookup, canonical root check, chamber membership
	// resolution). An honest proposer sends at most ~1 seal request per
	// 12-second slot, so the qtdSealPerPeerMax=20 / 10s window is
	// generous for honest peers and only blocks flood attacks.
	if !n.allowQTDSealFromPeer(msg.From) {
		nodeLog.Warn("NODE-R12-H01: QTD seal request from peer %s rate-limited (per-peer flood protection)",
			msg.From.String())
		return
	}

	data := msg.Payload
	if len(data) < 40 {
		return
	}

	qpos := n.blockProducer.QPOS()
	if !qpos.HasChambers() {
		return
	}

	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		return
	}

	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		return
	}

	executive := coordinator.GetExecutiveChamber()
	if executive == nil || !executive.IsActive() {
		return
	}

	slot := binary.BigEndian.Uint64(data[0:8])
	blockHash := types.Hash{}
	copy(blockHash[:], data[8:40])

	// QUANTUM-FIX (B-5): Only the current slot proposer may broadcast
	// seal requests. Any peer broadcasting MsgTypeQTDSealRequest could trick
	// executive members into participating in TSS sessions for arbitrary
	// (slot, blockHash) pairs. The proposer for the slot is determined
	// deterministically by qpos.GetProposerForSlot.
	proposer, err := qpos.GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		nodeLog.Warn("QTD seal request: cannot resolve proposer for slot %d (B-5): %v", slot, err)
		return
	}
	senderAddr, found := n.resolveSenderAddress(msg.From)
	if !found {
		nodeLog.Warn("QTD seal request: cannot resolve sender address, rejecting (B-5)")
		return
	}
	if !bytes.Equal(senderAddr[:], proposer.Address[:]) {
		nodeLog.Warn("QTD seal request: sender %x is not the proposer %x for slot %d, rejecting (B-5)",
			senderAddr[:8], proposer.Address[:8], slot)
		return
	}

	// QUANTUM-FIX (R4-CORE-04): Verify blockHash matches the canonical
	// chain root for this slot. A malicious proposer could otherwise request
	// seals for non-canonical fork blocks. If the slot root is not yet known
	// (block not yet processed on this node), we allow the request — the
	// canonical check is enforced again in qfs.AggregateAndCompleteSeal and
	// qfs.SubmitCompletedSeal before the seal is finalized.
	if canonicalRoot, ok := qpos.GetSlotBlockRoot(slot); ok {
		if canonicalRoot != blockHash {
			nodeLog.Warn("QTD seal request: blockHash %s is not canonical %s for slot %d, rejecting (R4-CORE-04)",
				blockHash.String(), canonicalRoot.String(), slot)
			return
		}
	}

	// R7 P0-1 FIX: Executive members no longer produce partial signatures
	// via validatorKey.Sign. The proposer computes the full QTD threshold
	// signature asynchronously via qfs.AggregateAndCompleteSeal. This
	// notification is used only for observability — executive members can
	// log that a seal is in progress and prepare for incoming TSS protocol
	// messages (Round1/Round2) in distributed mode.
	if executive.IsMember(n.blockProducer.validatorIdx) {
		nodeLog.Debug("QTD seal request received from proposer for slot %d (blockHash=%s) — awaiting TSS protocol messages",
			slot, blockHash.String())
	}
}

// handleQTDPartialSeal processes an incoming partial seal from an executive member.
// It forwards the partial seal to the QTD finality engine for aggregation.
//
// R7 P0-1 NOTE (2026-07-17): This partial-seal collection path is DEPRECATED.
// The production path is qfs.AggregateAndCompleteSeal (called by the proposer
// in requestQTDSeal). This handler is retained for backward compatibility with
// nodes that still use the old flow, but partial sigs produced by
// validatorKey.Sign will be rejected by AggregatePartialSignatures in local
// mode (fail-closed).
//
// QUANTUM-FIX (B-3): Verify the sender's validator address maps to the
// claimed validatorIndex. Without this, any peer could submit a partial seal
// claiming to be any executive member, potentially reaching the threshold
// with forged signatures.
//
// NODE-R12-H01 FIX (2026-07-20): Per-peer rate limit. qfs.SubmitPartialSeal
// performs Dilithium3 signature verification (~1ms per call) which is
// expensive. A compromised executive member could otherwise flood the inbound
// path with MsgTypeQTDPartialSeal messages, each triggering signature
// verification. The rate limit caps this at qtdSealPerPeerMax per
// qtdSealPerPeerWindow per peer.
func (n *Node) handleQTDPartialSeal(msg p2p.PeerMessage) {
	// NODE-R12-H01: Per-peer rate limit. Enforced BEFORE any expensive
	// work (Dilithium3 signature verification in qfs.SubmitPartialSeal).
	// An honest executive member sends at most ~1 partial seal per slot
	// (12-second tick), so qtdSealPerPeerMax=20 / 10s is generous for
	// honest peers and only blocks flood attacks.
	if !n.allowQTDSealFromPeer(msg.From) {
		nodeLog.Warn("NODE-R12-H01: QTD partial seal from peer %s rate-limited (per-peer flood protection)",
			msg.From.String())
		return
	}

	data := msg.Payload
	if len(data) < 20 {
		return
	}

	qpos := n.blockProducer.QPOS()
	if !qpos.HasChambers() {
		return
	}

	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		return
	}

	slot := binary.BigEndian.Uint64(data[0:8])
	validatorIndex := int(binary.BigEndian.Uint64(data[8:16])) // #nosec G115 -- validator count fits in int
	sigLen := binary.BigEndian.Uint32(data[16:20])

	// P2P-R10-H2 (2026-07-19) FIX: Hard-cap sigLen and use uint64
	// arithmetic for the length check. Without this:
	//   1. A malicious peer could send sigLen=0xFFFFFFFF (4GB), and on
	//      32-bit systems `int(sigLen)` overflows to -1, making
	//      `20 + int(sigLen) == 19` — the subsequent bounds check
	//      `len(data) < 19` passes for any payload, and
	//      `data[20 : 20+sigLen]` slices with a negative-or-wrapped end,
	//      causing a panic or OOM.
	//   2. Even on 64-bit systems, a 4GB sigLen allocation in
	//      `data[20 : 20+sigLen]` is a trivial OOM DoS.
	// The QTD protocol uses Dilithium3 partial signatures (3293 bytes);
	// 4096 is a generous hard cap that accommodates any reasonable
	// future signature scheme without allowing DoS.
	const maxQTDPartialSealSigLen uint32 = 4096
	if sigLen > maxQTDPartialSealSigLen {
		nodeLog.Warn("QTD partial seal: sigLen %d exceeds hard cap %d, rejecting (P2P-R10-H2) slot=%d validatorIndex=%d",
			sigLen, maxQTDPartialSealSigLen, slot, validatorIndex)
		return
	}
	// Use uint64 arithmetic to avoid any platform-dependent int overflow.
	if uint64(len(data)) < 20+uint64(sigLen) {
		return
	}
	signature := data[20 : 20+sigLen]

	// QUANTUM-FIX (B-3): Bind sender to validatorIndex. The
	// validatorIndex in the payload must match the sender's validator
	// address. Without this, any peer could claim any validatorIndex and
	// inject forged partial seals. validateSenderParticipantID verifies
	// that senderAddr maps to (validatorIndex + 1) as a 1-based TSS
	// participant ID.
	senderAddr, found := n.resolveSenderAddress(msg.From)
	if !found {
		nodeLog.Warn("QTD partial seal: cannot resolve sender address, rejecting (B-3) slot=%d validatorIndex=%d",
			slot, validatorIndex)
		return
	}
	if !n.validateSenderParticipantID(senderAddr, validatorIndex+1) {
		nodeLog.Warn("QTD partial seal: sender %x does not match validatorIndex %d, rejecting (B-3) slot=%d",
			senderAddr[:8], validatorIndex, slot)
		return
	}

	// Submit the partial seal to the QTD finality engine.
	if err := qfs.SubmitPartialSeal(validatorIndex, slot, signature); err != nil {
		// Expected errors: duplicate, invalid signature, not a sealer, etc.
		return
	}

	// P1-6: After successful submission, check if the seal is now complete.
	// completeSealLocked (inside SubmitPartialSeal) handles finalization
	// asynchronously via a goroutine, so we just trigger the flow update here.
	flow := n.blockProducer.ThreeChambersFlow()
	if flow != nil {
		_ = flow.CompleteSeal(slot)
		_ = flow.FinalizeBlock(slot)
	}
}

// requestQTDSeal is called by the block producer after a block is approved
// to request the QTD threshold signature for the seal.
//
// R7 P0-1 FIX (2026-07-17): The proposer now computes the full QTD threshold
// signature asynchronously via qfs.AggregateAndCompleteSeal, which routes to
// distributeTSSSignNoFallback (distributed mode, strict P2P multi-party
// signing) or SignWithRetry (local mode). The MsgTypeQTDSealRequest broadcast
// is kept as a notification so executive members know a seal is in progress
// and can prepare for incoming TSS protocol messages.
//
// The threshold signing runs in a goroutine to avoid blocking the 12-second
// slot tick — distributed signing may take up to 20 seconds (Round1 + Round2
// timeouts).
func (n *Node) requestQTDSeal(slot uint64, blockHash types.Hash) {
	if n.p2pHost == nil {
		return
	}

	// Broadcast the seal request notification (B-5 authenticated on the
	// receiver side in handleQTDSealRequest).
	msg := make([]byte, 40)
	binary.BigEndian.PutUint64(msg[0:8], slot)
	copy(msg[8:40], blockHash[:])
	_ = n.p2pHost.BroadcastQTDSealRequest(msg)

	// Asynchronously compute the QTD threshold signature and complete the seal.
	// This is the production path — the broken partial-seal collection in
	// handleQTDPartialSeal is deprecated.
	go n.computeAndCompleteQTDSeal(slot, blockHash)
}

// computeAndCompleteQTDSeal computes the QTD threshold signature for the given
// slot and submits it to the QTD finality engine. Called asynchronously from
// requestQTDSeal to avoid blocking the slot tick.
//
// P2P-R11-H02 (2026-07-20) FIX: Previously AggregateAndCompleteSeal failure
// (e.g., due to transient network issues or partial validator timeouts) was
// logged and the goroutine returned, leaving the slot's QTD seal permanently
// missing — the block could not be finalized. We now retry with exponential
// backoff (1s, 2s, 4s) up to 3 attempts before giving up. Each retry
// re-fetches the chamber members in case the executive chamber rotated.
//
// NODE-R12-H01 (2026-07-20) FIX: Concurrency semaphore. Without a bound, a
// burst of slot seal requests (e.g., 10 slots finalized in quick succession
// during sync, or retries piling up under network stress) could spawn an
// unbounded number of computeAndCompleteQTDSeal goroutines, each performing
// Dilithium3 aggregate signing (~50-200ms per attempt, up to 3 retries).
// This would exhaust CPU and cause the slot tick to miss its 12-second
// deadline. The semaphore (cap=MaxConcurrentQTDSeals=3) bounds the
// concurrency; goroutines that cannot acquire within
// qtdSealAcquireTimeout=2s exit early and the slot tick retries on the
// next iteration.
func (n *Node) computeAndCompleteQTDSeal(slot uint64, blockHash types.Hash) {
	// P2P-R10-H1 (2026-07-19) FIX: Top-level panic recovery for the
	// asynchronously-spawned QTD seal goroutine. Without this defer, any
	// panic in AggregateAndCompleteSeal (e.g., nil pointer in chambers
	// coordinator, threshold math overflow on a malicious partial-sig)
	// would propagate up the goroutine and crash the entire node — taking
	// down the block producer and halting consensus. With recovery, the
	// panic is logged with full slot/blockHash context and the goroutine
	// exits cleanly; the next slot tick will retry the seal.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("QTD seal: computeAndCompleteQTDSeal panic recovered (slot=%d blockHash=%s): %v",
				slot, blockHash.String(), r)
		}
	}()

	// NODE-R12-H01: Acquire a concurrency slot before doing any expensive
	// Dilithium3 work. If we cannot acquire within qtdSealAcquireTimeout,
	// it means MaxConcurrentQTDSeals goroutines are already in flight —
	// exit early so this goroutine doesn't pile up. The slot tick will
	// retry on the next iteration; if the seal is permanently missed, the
	// block will not be finalized and the next proposer will skip this
	// slot (consistent with consensus rules for unfinalized slots).
	if !n.acquireQTDSealSlot() {
		nodeLog.Warn("NODE-R12-H01: QTD seal semaphore full (cap=%d), giving up on slot %d (blockHash=%s) — slot tick will retry",
			MaxConcurrentQTDSeals, slot, blockHash.String())
		return
	}
	defer n.releaseQTDSealSlot()

	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}

	qpos := n.blockProducer.QPOS()
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		return
	}

	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		return
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		return
	}

	// Get the executive chamber members as sealers.
	members := executive.Members()
	if len(members) == 0 {
		nodeLog.Warn("QTD seal: executive chamber has no members for slot %d", slot)
		return
	}

	// P2P-R11-H02: Retry with exponential backoff on transient failures.
	// Network jitter or partial validator timeouts can cause the first
	// AggregateAndCompleteSeal to fail; without retry the slot's seal
	// would be permanently missing and the block could not be finalized.
	const maxRetries = 3
	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Re-fetch chamber on retry — executive chamber may have rotated.
		if attempt > 1 {
			executive = coordinator.GetExecutiveChamber()
			if executive == nil {
				nodeLog.Warn("QTD seal: executive chamber became nil on retry %d for slot %d",
					attempt, slot)
				return
			}
			members = executive.Members()
			if len(members) == 0 {
				nodeLog.Warn("QTD seal: executive chamber has no members on retry %d for slot %d",
					attempt, slot)
				return
			}
			time.Sleep(backoff)
			backoff *= 2
		}

		// Compute the threshold signature and complete the seal. This routes to
		// distributeTSSSignNoFallback (distributed mode) or SignWithRetry (local
		// mode). Both paths enforce t-of-n threshold security.
		err := qfs.AggregateAndCompleteSeal(slot, members)
		if err == nil {
			nodeLog.Info("QTD seal: threshold signature computed and seal completed for slot %d (blockHash=%s, members=%d, attempt=%d)",
				slot, blockHash.String(), len(members), attempt)

			// Trigger the Three Chambers flow update.
			flow := n.blockProducer.ThreeChambersFlow()
			if flow != nil {
				_ = flow.CompleteSeal(slot)
				_ = flow.FinalizeBlock(slot)
			}
			return
		}

		lastErr = err
		nodeLog.Warn("QTD seal: AggregateAndCompleteSeal failed for slot %d (blockHash=%s, attempt=%d/%d): %v",
			slot, blockHash.String(), attempt, maxRetries, err)
	}

	nodeLog.Error("QTD seal: all retry attempts exhausted for slot %d (blockHash=%s, lastErr=%v)",
		slot, blockHash.String(), lastErr)
}

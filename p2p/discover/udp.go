// Quantaureum Node source, version 1.0.0.
package discover

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/p2p/enode"
)

// udpLog is the package logger for discover/udp.go.
//
// P2-DEADLINE FIX (R29, 2026-07-26): Previously SetWriteDeadline errors
// were silently discarded, which could mask underlying socket failures
// (e.g., closed connection, OS buffer exhaustion). Errors are now logged
// at warning level so operators can diagnose UDP transport degradation.
var udpLog = logging.Global().WithModule("p2p.discover")

const (
	udpPacketBufSize   = 1280
	udpReadTimeout     = 2 * time.Second
	udpWriteTimeout    = 2 * time.Second
	udpMaxPacketSize   = 1280
	udpRespTimeout     = 5 * time.Second
	udpCleanupInterval = 30 * time.Second
	udpPendingTimeout  = 15 * time.Second
	// udpRestartBackoff is the pause before the read loop is restarted
	// after a panic (AUDIT-FULL H-3). It bounds the restart rate to at
	// most one attempt per second even under sustained panic triggers.
	udpRestartBackoff = 1 * time.Second
)

// SECURITY (audit P2P-08): Rate limiting and endpoint-proof constants.
const (
	// pingRateLimitCount is the max PING responses per IP per window.
	// PING/PONG is ~1:1 amplification, so this is more lenient than FINDNODE.
	pingRateLimitCount = 10
	// pingRateWindow is the PING rate limit sliding window.
	pingRateWindow = 10 * time.Second
	// verifiedPeerTTL is how long a PING-verified endpoint is trusted
	// to receive FINDNODE responses without a new PING. This is the
	// "bond" lifetime — an IP that completed a PING/PONG exchange with
	// us within this window is considered to have proven endpoint
	// reachability.
	verifiedPeerTTL = 5 * time.Minute
	// rateLimiterMaxEntries is the cap before triggering cleanup.
	rateLimiterMaxEntries = 1000

	// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): Maximum number of concurrent
	// verification PING goroutines. Each incoming PING from an unverified IP
	// triggers a verification PING (to prove the sender can receive packets).
	// Without this cap, an attacker flooding us with PINGs from many spoofed
	// IPs could spawn unbounded goroutines (each blocking up to udpRespTimeout).
	// 100 concurrent goroutines × 5s timeout = at most 100 goroutines blocked
	// at any time, which is negligible memory (~100KB of stack).
	maxConcurrentVerificationPINGs = 100
)

// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): verificationSem is a semaphore
// that limits the number of concurrent verification PING goroutines. This
// prevents goroutine exhaustion when an attacker floods us with PINGs from
// many spoofed IPs. The semaphore is package-level (not per-transport) because
// the goroutine cost is process-wide, not per-transport.
var verificationSem = make(chan struct{}, maxConcurrentVerificationPINGs)

var (
	errUDPClosed       = errors.New("UDP transport closed")
	errUDPTimeout      = errors.New("UDP request timeout")
	errUDPInvalidReply = errors.New("invalid UDP reply")
)

type udpPacket struct {
	data []byte
	from *net.UDPAddr
}

// ipRateEntry tracks per-IP rate limiting state for FINDNODE requests.
// SECURITY (audit P2-06): Prevents reflection amplification attacks.
type ipRateEntry struct {
	count     int
	windowEnd time.Time
}

type pendingRequest struct {
	callback     func(any, error)
	deadline     time.Time
	expectedAddr *net.UDPAddr // CRITICAL: Verify response sender matches expected
}

// safeCallback invokes a discovery callback with panic recovery.
// R31-P3 FIX (P3-5, 2026-07-28): Previously, a panicking callback would
// kill the UDP packet-processing goroutine (or the cleanupPending loop),
// silently disabling node discovery. The node would appear healthy but
// be unable to find new peers. This wrapper logs the panic and continues,
// treating the callback as failed (nil + error) so the caller can clean
// up state without crashing the transport.
func safeCallback(cb func(any, error), resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			udpLog.Error("discovery callback panic recovered", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	cb(resp, err)
}

type UDPTransport struct {
	conn      *net.UDPConn
	localNode *enode.Node
	table     *Table

	packetCh  chan *udpPacket
	pending   map[uint32]*pendingRequest
	pendingMu sync.Mutex

	// SECURITY (audit P2-06): IP rate limiter for FINDNODE to prevent
	// reflection amplification attacks (16.5x amplification factor).
	findNodeRateLimiter map[string]*ipRateEntry

	// SECURITY (audit P2P-08): PING rate limiter to prevent PING reflection
	// abuse (unlimited PONG responses to spoofed/source-flooded PINGs).
	pingRateLimiter map[string]*ipRateEntry

	// SECURITY (audit P2P-08): Verified peers — IPs that have completed a
	// PING/PONG exchange with us (WE sent a PING and received a matching
	// PONG). This proves they can receive packets at that address, not just
	// send them. FINDNODE is only answered for verified IPs, preventing
	// ~16× reflection amplification where an attacker spoofs the source IP
	// to redirect NEIGHBORS responses to a victim.
	//
	// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): Previously, this was set
	// in handlePing whenever ANY PING was received (even spoofed). Now it
	// is only set in handlePong when a PONG matches a PING we initiated.
	// The value is the timestamp of the last completed PING/PONG exchange.
	verifiedPeers map[string]time.Time

	rateLimiterMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

func NewUDPTransport(ctx context.Context, localNode *enode.Node, table *Table, addr string) (*UDPTransport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	t := &UDPTransport{
		conn:      conn,
		localNode: localNode,
		table:     table,
		packetCh:  make(chan *udpPacket, 256),
		pending:   make(map[uint32]*pendingRequest),
		ctx:       ctx,
		cancel:    cancel,
	}

	t.wg.Add(2)
	go t.readLoop()
	go t.handleLoop()

	// R32-P1-06 FIX (2026-07-28): Wire the transport as the table's pinger
	// so that full buckets can probe their oldest entry and evict stale
	// nodes, allowing honest new nodes to join the routing table.
	if table != nil {
		table.SetPinger(t)
	}

	return t, nil
}

func (t *UDPTransport) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()

	t.cancel()
	t.conn.Close()
	t.wg.Wait()
}

func (t *UDPTransport) readLoop() {
	defer t.wg.Done()
	// AUDIT-FULL H-3 FIX (2026-08-14): Previously the recover below let
	// the goroutine exit permanently after a panic, silently disabling
	// node discovery for the rest of the process lifetime. Now the loop
	// is restarted (with a backoff) until the transport is closed, so a
	// single malformed packet only costs one second of discovery outage.
	for {
		t.readLoopOnce()
		if t.ctx.Err() != nil {
			return
		}
		udpLog.Warn("readLoop: restarting after panic", map[string]any{
			"backoff": udpRestartBackoff.String(),
		})
		select {
		case <-time.After(udpRestartBackoff):
		case <-t.ctx.Done():
			return
		}
	}
}

// readLoopOnceHook is nil in production. Tests assign it to inject a
// panic into readLoopOnce so the supervisor restart (AUDIT-FULL H-3)
// can be verified deterministically.
var readLoopOnceHook func()

func (t *UDPTransport) readLoopOnce() {
	// CRIT-08 (R17, 2026-07-23): Long-running UDP read loop. A panic
	// (e.g., from a malformed packet triggering an unguarded type
	// assertion) would crash the node. The recover lets this iteration
	// exit cleanly; readLoop restarts it (H-3).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "UDP readLoop panic recovered: %v\n", r)
		}
	}()

	if readLoopOnceHook != nil {
		readLoopOnceHook()
	}

	buf := make([]byte, udpPacketBufSize)
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// P2-P2P-DEADLINE FIX (R30, 2026-07-27): Previously the SetReadDeadline
		// error was silently ignored. If SetReadDeadline fails, the socket may
		// be in a degraded state — log at Warn so operators can diagnose UDP
		// transport issues. Do not break the loop: ReadFromUDP will return its
		// own error if the socket is unusable, which is handled below.
		if err := t.conn.SetReadDeadline(time.Now().Add(udpReadTimeout)); err != nil {
			udpLog.Warn("readLoop: SetReadDeadline failed", map[string]any{
				"err": err.Error(),
			})
		}
		n, from, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			if t.ctx.Err() != nil {
				return
			}
			continue
		}

		packet := &udpPacket{
			data: make([]byte, n),
			from: from,
		}
		copy(packet.data, buf[:n])

		select {
		case t.packetCh <- packet:
		case <-t.ctx.Done():
			return
		default:
		}
	}
}

func (t *UDPTransport) handleLoop() {
	defer t.wg.Done()
	// CRIT-08 (R17, 2026-07-23): Long-running packet handler loop. A
	// panic in packet handling (e.g., from a malformed packet or a bug
	// in the enode parser) would crash the node. The recover lets the
	// goroutine exit cleanly; packet handling stops but the node keeps
	// running. readLoop will still drain packets into packetCh but they
	// won't be processed (acceptable degradation vs. node crash).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "UDP handleLoop panic recovered: %v\n", r)
		}
	}()

	cleanupTicker := time.NewTicker(udpCleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case packet := <-t.packetCh:
			t.handlePacket(packet)
		case <-cleanupTicker.C:
			t.cleanupPending()
			t.cleanupRateLimiters()
		}
	}
}

func (t *UDPTransport) handlePacket(packet *udpPacket) {
	if len(packet.data) < 1 {
		return
	}

	packetType := packet.data[0]
	payload := packet.data[1:]

	switch packetType {
	case 1:
		t.handlePing(packet.from, payload)
	case 2:
		t.handlePong(packet.from, payload)
	case 3:
		t.handleFindNode(packet.from, payload)
	case 4:
		t.handleNeighbors(packet.from, payload)
	}
}

func (t *UDPTransport) handlePing(from *net.UDPAddr, payload []byte) {
	if len(payload) < 4 {
		return
	}

	// SECURITY (audit P2P-08): Rate limit PING responses per IP to prevent
	// PING reflection abuse. Without this, an attacker can send unlimited
	// spoofed PINGs causing the node to flood the victim's IP with PONGs.
	if !t.allowPing(from.IP.String()) {
		return // silently drop rate-limited PINGs
	}

	reqID := binary.BigEndian.Uint32(payload[:4])

	pongPayload := make([]byte, 4+len(payload[4:]))
	binary.BigEndian.PutUint32(pongPayload[:4], reqID)
	copy(pongPayload[4:], payload[4:])

	pongPacket := make([]byte, 1+len(pongPayload))
	pongPacket[0] = 2
	copy(pongPacket[1:], pongPayload)

	// P2-DEADLINE FIX (R29, 2026-07-26): Check SetWriteDeadline error.
	// A failure here indicates the socket is in a bad state (closed, FD
	// exhausted, etc.); the subsequent WriteToUDP would also fail, so we
	// log and skip the write rather than silently discarding the error.
	if err := t.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
		udpLog.Warn("handlePong: SetWriteDeadline failed", map[string]any{
			"from": from.String(), "err": err.Error(),
		})
		return
	}
	if _, err := t.conn.WriteToUDP(pongPacket, from); err != nil {
		udpLog.Warn("handlePong: WriteToUDP failed", map[string]any{
			"from": from.String(), "err": err.Error(),
		})
	}

	// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): Do NOT call markVerified
	// here. Previously, receiving an unsigned PING immediately granted the
	// sender FINDNODE qualification — an attacker could spoof a PING from
	// a victim's IP, get it marked as "verified", then send spoofed
	// FINDNODEs to trigger large NEIGHBORS responses to the victim
	// (~16× reflection amplification). The PING has no signature and the
	// source IP is trivially spoofable in UDP.
	//
	// Instead, we send our OWN PING to the sender's IP. Only when we receive
	// a PONG matching our PING (in handlePong) do we mark the IP as verified
	// — this proves the sender can actually RECEIVE packets at that address
	// (the PING/PONG exchange requires bidirectional reachability, which
	// spoofing cannot provide).
	//
	// The verification PING is sent in a goroutine because Ping() blocks
	// waiting for the PONG (up to udpRespTimeout). A semaphore
	// (verificationSem) caps the number of concurrent verification PINGs to
	// prevent goroutine exhaustion under PING-flooding attacks. If the
	// semaphore is full, the verification PING is skipped — the peer can
	// retry on their next PING.
	//
	// We also skip the verification PING if the peer is already verified
	// (no need to re-verify within the verifiedPeerTTL window) or if the
	// transport is closing (ctx is nil or ctx.Err() != nil).
	//
	// P2-NIL-LOCALNODE FIX (R29, 2026-07-26): Also require t.localNode != nil,
	// because the verification goroutine calls t.Ping(node), which needs
	// t.localNode to construct the PING payload. Skipping the verification
	// PING when localNode is nil avoids spawning a goroutine that's
	// guaranteed to fail (and previously panicked).
	if t.ctx != nil && t.ctx.Err() == nil && t.localNode != nil &&
		len(payload) >= 4+32 && !t.isVerified(from.IP.String()) {
		var nodeID enode.ID
		copy(nodeID[:], payload[4:36])
		if !nodeID.IsEmpty() {
			// Non-blocking semaphore acquire — if full, skip this verification.
			select {
			case verificationSem <- struct{}{}:
				go func() {
					defer func() { <-verificationSem }()
					// Re-check ctx after acquiring the semaphore (the transport
					// may have closed while we were waiting for the semaphore).
					if t.ctx == nil || t.ctx.Err() != nil {
						return
					}
					// Construct a minimal enode.Node for the Ping call.
					// The node ID comes from the PING payload; the address
					// comes from the UDP source.
					node := enode.NewNode(nodeID, from.IP, from.Port, from.Port)
					// Ping blocks until PONG or timeout. On success, handlePong
					// marks the IP as verified. On failure/timeout, the peer
					// remains unverified and their FINDNODE requests will be
					// dropped — which is the correct fail-closed behavior.
					_ = t.Ping(node)
				}()
			default:
				// Semaphore full — too many concurrent verification PINGs.
				// Skip this one; the peer can retry on their next PING.
			}
		}
	}

	if t.table != nil {
		// SECURITY FIX: Do NOT add nodes from unsigned ping packets.
		// Attackers can send forged ping packets with arbitrary nodeIDs to inject fake nodes.
		// Only add nodes after successful ping/pong exchange (bidirectional verification).
		//
		//  AUDIT NOTE: The current behavior is intentionally safe — nodes
		// are NEVER added to the routing table from incoming ping packets alone.
		// Nodes enter the table only via:
		//   1. AddTrustedNode (bootstrap/persisted nodes, skips ENR validation)
		//   2. Successful ping→pong exchange (bidirectional reachability verified)
		//
		// AUDIT (2026) R3-P2P-05 CLEANUP: Removed the dead `nodeID` extraction
		// and `if !nodeID.IsEmpty()` no-op block. The previous code extracted the
		// nodeID only to discard it (`_ = nodeID`), which was misleading. The
		// security guarantee — reject-by-default for routing table insertion from
		// unsigned pings — is preserved by simply doing nothing here. A future
		// enhancement (QZKP-001) may add cryptographic ping signature verification
		// to enable ping-based node addition as a latency optimization; until then
		// the safe reject-by-default behavior remains in effect.
	}
}

func (t *UDPTransport) handlePong(from *net.UDPAddr, payload []byte) {
	if len(payload) < 4 {
		return
	}

	reqID := binary.BigEndian.Uint32(payload[:4])

	t.pendingMu.Lock()
	req, exists := t.pending[reqID]
	if exists {
		delete(t.pending, reqID)
	}
	t.pendingMu.Unlock()

	if exists && req.callback != nil {
		safeCallback(req.callback, payload[4:], nil)
	}

	// SECURITY FIX H-4: Only update node activity if the pong corresponds
	// to a pending ping request from the expected address. This prevents an
	// attacker from forging pong packets to keep fake nodes "alive" in the
	// routing table.
	if t.table != nil && exists {
		if req.expectedAddr != nil && !sameUDPAddr(req.expectedAddr, from) {
			// Pong from unexpected address — reject to prevent activity spoofing.
			return
		}
		// R32-P1-08 FIX (2026-07-28): Verify the PONG's RecipientID matches
		// our local node ID. The PONG echoes back the PING sender's node ID
		// (our localNode.ID()). If this doesn't match our local node ID, the
		// PONG was meant for a different node (replay/cross-node attack) and
		// must be rejected. Without this check, an attacker who captures a
		// PONG meant for node A could replay it to node B to falsely mark
		// a remote node as "active" in B's routing table.
		nodeID := t.extractNodeID(payload[4:])
		if t.localNode != nil && !nodeID.IsEmpty() && nodeID != t.localNode.ID() {
			udpLog.Warn("handlePong: PONG RecipientID mismatch — rejecting (possible replay)",
				map[string]any{"from": from.String()})
			return
		}
		if !nodeID.IsEmpty() {
			t.table.UpdateNodeActivity(nodeID)
		}
	}

	// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): Mark the sender as a verified
	// peer ONLY after we receive a PONG that matches a PING we sent. This is
	// the "endpoint proof" — we sent a PING to this IP and they responded with
	// a PONG, proving they can receive packets at this address. Without this,
	// an attacker could spoof a PING (which has no signature) and immediately
	// gain FINDNODE qualification, enabling reflection amplification attacks.
	//
	// Conditions for marking as verified:
	//  1. The PONG must match a pending PING (exists == true). This means WE
	//     initiated the PING, not the peer. A PONG without a matching PING is
	//     unsolicited and ignored.
	//  2. The PONG must come from the address we sent the PING to
	//     (req.expectedAddr matches `from`). This prevents an attacker from
	//     sending a PONG from a different address to get that address verified.
	//     Note: if expectedAddr is nil (legacy/buggy pending entry), we
	//     conservatively skip verification — fail-closed.
	//
	// This replaces the old behavior where handlePing called markVerified
	// immediately upon receiving ANY PING (even spoofed ones). Now, only a
	// completed PING→PONG exchange (initiated by us) grants verification.
	if exists {
		if req.expectedAddr != nil && sameUDPAddr(req.expectedAddr, from) {
			t.markVerified(from.IP.String())
		}
	}
}

func (t *UDPTransport) handleFindNode(from *net.UDPAddr, payload []byte) {
	if len(payload) < 36 {
		return
	}

	// SECURITY (audit P2P-08): Require endpoint proof before responding to
	// FINDNODE. The requester must have recently sent us a PING (proving
	// they can receive packets at their claimed source address). This
	// prevents ~16× reflection amplification attacks where an attacker
	// spoofs the source IP to cause large NEIGHBORS responses to be sent
	// to a victim. The attacker cannot complete the PING/PONG exchange
	// from a spoofed address because they would need to receive the PONG.
	if !t.isVerified(from.IP.String()) {
		return // no endpoint proof — silently drop
	}

	// SECURITY (audit P2-06): Rate limit FINDNODE per IP to prevent reflection
	// amplification attacks. Max 5 requests per 10 seconds per IP.
	if !t.allowFindNode(from.IP.String()) {
		return // silently drop rate-limited requests
	}

	reqID := binary.BigEndian.Uint32(payload[:4])
	var target enode.ID
	copy(target[:], payload[4:36])

	var closest []*enode.Node
	if t.table != nil {
		closest = t.table.FindClosest(target, 16)
	}

	neighborsPayload := encodeUDPNeighbors(closest)

	packet := make([]byte, 1+4+len(neighborsPayload))
	packet[0] = 4
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	copy(packet[5:], neighborsPayload)

	// P2-DEADLINE FIX (R29, 2026-07-26): Check SetWriteDeadline error.
	if err := t.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
		udpLog.Warn("replyNeighbors: SetWriteDeadline failed", map[string]any{
			"from": from.String(), "err": err.Error(),
		})
		return
	}
	if _, err := t.conn.WriteToUDP(packet, from); err != nil {
		udpLog.Warn("replyNeighbors: WriteToUDP failed", map[string]any{
			"from": from.String(), "err": err.Error(),
		})
	}
}

// allowFindNode checks if the given IP is within the rate limit for FINDNODE.
// SECURITY (audit P2-06): 5 requests per 10 seconds per IP.
func (t *UDPTransport) allowFindNode(ip string) bool {
	t.rateLimiterMu.Lock()
	defer t.rateLimiterMu.Unlock()

	now := time.Now()
	if t.findNodeRateLimiter == nil {
		t.findNodeRateLimiter = make(map[string]*ipRateEntry)
	}

	entry, exists := t.findNodeRateLimiter[ip]
	if !exists || now.After(entry.windowEnd) {
		// Clean up expired entries to prevent unbounded map growth
		if len(t.findNodeRateLimiter) > 1000 {
			for k, v := range t.findNodeRateLimiter {
				if now.After(v.windowEnd) {
					delete(t.findNodeRateLimiter, k)
				}
			}
		}
		t.findNodeRateLimiter[ip] = &ipRateEntry{count: 1, windowEnd: now.Add(10 * time.Second)}
		return true
	}

	if entry.count >= 5 {
		return false
	}
	entry.count++
	return true
}

// allowPing checks if the given IP is within the rate limit for PING responses.
// SECURITY (audit P2P-08): 10 PINGs per 10 seconds per IP. PING/PONG is ~1:1
// amplification, so the limit is more lenient than FINDNODE (5 per 10s).
func (t *UDPTransport) allowPing(ip string) bool {
	t.rateLimiterMu.Lock()
	defer t.rateLimiterMu.Unlock()

	now := time.Now()
	if t.pingRateLimiter == nil {
		t.pingRateLimiter = make(map[string]*ipRateEntry)
	}

	entry, exists := t.pingRateLimiter[ip]
	if !exists || now.After(entry.windowEnd) {
		// Clean up expired entries to prevent unbounded map growth
		if len(t.pingRateLimiter) > rateLimiterMaxEntries {
			for k, v := range t.pingRateLimiter {
				if now.After(v.windowEnd) {
					delete(t.pingRateLimiter, k)
				}
			}
		}
		t.pingRateLimiter[ip] = &ipRateEntry{count: 1, windowEnd: now.Add(pingRateWindow)}
		return true
	}

	if entry.count >= pingRateLimitCount {
		return false
	}
	entry.count++
	return true
}

// markVerified records that an IP has completed a PING/PONG exchange with us,
// establishing endpoint proof for FINDNODE responses.
// SECURITY (audit P2P-08): Prevents reflection amplification by requiring
// bidirectional reachability before sending large NEIGHBORS responses.
//
// P2-HANDLEPING-AUTH FIX (R29, 2026-07-26): This is now called ONLY from
// handlePong (when a PONG matches a PING we sent), NOT from handlePing.
// This ensures the peer has proven they can receive packets at this address,
// not just send them.
func (t *UDPTransport) markVerified(ip string) {
	t.rateLimiterMu.Lock()
	defer t.rateLimiterMu.Unlock()

	if t.verifiedPeers == nil {
		t.verifiedPeers = make(map[string]time.Time)
	}
	t.verifiedPeers[ip] = time.Now()
}

// isVerified checks if an IP has recently sent a PING (endpoint proof).
// SECURITY (audit P2P-08): FINDNODE is only answered for verified IPs.
func (t *UDPTransport) isVerified(ip string) bool {
	t.rateLimiterMu.Lock()
	defer t.rateLimiterMu.Unlock()

	if t.verifiedPeers == nil {
		return false
	}
	lastSeen, exists := t.verifiedPeers[ip]
	if !exists {
		return false
	}
	return time.Since(lastSeen) < verifiedPeerTTL
}

// cleanupRateLimiters removes expired entries from all rate limiter maps.
// Called periodically by the handleLoop cleanup ticker to prevent unbounded
// growth. SECURITY (audit P2P-08): bounds verifiedPeers and pingRateLimiter.
func (t *UDPTransport) cleanupRateLimiters() {
	t.rateLimiterMu.Lock()
	defer t.rateLimiterMu.Unlock()

	now := time.Now()

	// Cleanup findNodeRateLimiter
	for k, v := range t.findNodeRateLimiter {
		if now.After(v.windowEnd) {
			delete(t.findNodeRateLimiter, k)
		}
	}

	// Cleanup pingRateLimiter
	for k, v := range t.pingRateLimiter {
		if now.After(v.windowEnd) {
			delete(t.pingRateLimiter, k)
		}
	}

	// Cleanup verifiedPeers (TTL is longer — 5 minutes)
	cutoff := now.Add(-verifiedPeerTTL)
	for k, v := range t.verifiedPeers {
		if v.Before(cutoff) {
			delete(t.verifiedPeers, k)
		}
	}
}

func (t *UDPTransport) handleNeighbors(from *net.UDPAddr, payload []byte) {
	if len(payload) < 4 {
		return
	}

	reqID := binary.BigEndian.Uint32(payload[:4])

	t.pendingMu.Lock()
	req, exists := t.pending[reqID]
	if exists {
		delete(t.pending, reqID)
	}
	t.pendingMu.Unlock()

	nodes := decodeUDPNeighbors(payload[4:])
	if exists && req.callback != nil {
		safeCallback(req.callback, nodes, nil)
	}

	// SECURITY FIX H-4: Only add nodes from neighbors responses that
	// correspond to a pending findNode request AND originate from the expected
	// address. Previously, any unsolicited neighbors packet could inject
	// arbitrary nodes into the routing table, enabling eclipse attacks.
	// This is the P2P equivalent of "ping signature verification": we verify
	// the response is for a request we actually sent to this peer.
	if t.table != nil && exists {
		// Verify the response comes from the address we sent the request to.
		if req.expectedAddr != nil && !sameUDPAddr(req.expectedAddr, from) {
			// Response from unexpected address — reject to prevent injection.
			return
		}

		// R32-P1-07 FIX (2026-07-28): Defense against Eclipse attacks via
		// malicious NEIGHBORS responses. Two layers of validation:
		//
		// 1. Pre-filter each node with ValidateNodeID before acquiring the
		//    table lock. This performs ENR signature verification (when an
		//    ENR is present) and IP routability checks. Dropping invalid
		//    nodes here reduces lock contention in AddNode and prevents
		//    attacker-controlled ENRs from polluting the routing table.
		//    Without this, an attacker responding to our FINDNODE could
		//    inject dozens of forged ENRs (signed by attacker-controlled
		//    keys) to flood the routing table with Sybil identities.
		//
		// 2. Subnet diversity cap: limit the number of accepted nodes per
		//    /24 subnet per NEIGHBORS response. Kademlia normally returns
		//    the K closest nodes to the target, which may legitimately span
		//    many subnets. However, an Eclipse attacker controlling a /24
		//    subnet would return many nodes all in that subnet. Capping
		//    per-subnet acceptance (maxNeighborsPerSubnet = 4) limits the
		//    attacker's ability to fill multiple buckets with colluding
		//    nodes from a single subnet, while still allowing legitimate
		//    multi-subnet diversity. The cap of 4 matches Ethereum's
		//    discv4 implementation heuristic.
		const maxNeighborsPerSubnet = 4
		subnetCounts := make(map[string]int, len(nodes))
		added := 0
		for _, n := range nodes {
			// Layer 1: ENR signature + IP routability pre-validation.
			if err := ValidateNodeID(n); err != nil {
				udpLog.Debug("handleNeighbors: dropping invalid node from NEIGHBORS response",
					map[string]any{"err": err.Error()})
				continue
			}

			// Layer 2: per-/24-subnet diversity cap.
			if n.IP() != nil {
				subnet := ipToSubnet(n.IP().String())
				if subnetCounts[subnet] >= maxNeighborsPerSubnet {
					udpLog.Debug("handleNeighbors: subnet cap reached, dropping node",
						map[string]any{"subnet": subnet})
					continue
				}
				subnetCounts[subnet]++
			}

			t.table.AddNode(n) // #nosec G104 -- non-critical, errors logged inside
			added++
		}
		if added == 0 && len(nodes) > 0 {
			udpLog.Warn("handleNeighbors: all nodes from response rejected by validation",
				map[string]any{"from": from.String(), "total": len(nodes)})
		}
	}
}

// sameUDPAddr returns true if two UDP addresses have the same IP and port.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

func (t *UDPTransport) Ping(node *enode.Node) error {
	// P2-NIL-LOCALNODE FIX (R29, 2026-07-26): Defensive nil check for
	// t.localNode. handlePing spawns a verification PING goroutine that
	// calls Ping; if the transport was constructed without a localNode
	// (e.g., in tests or misconfigured production paths), accessing
	// t.localNode.ID() would panic and crash the goroutine. Return an
	// error instead so the caller (and the goroutine in handlePing) can
	// handle it gracefully.
	if t.localNode == nil {
		return fmt.Errorf("Ping: transport localNode is nil")
	}

	reqID := t.nextReqID()

	pingPayload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(pingPayload[:4], reqID)
	copy(pingPayload[4:], t.localNode.ID().Bytes())

	packet := make([]byte, 1+len(pingPayload))
	packet[0] = 1
	copy(packet[1:], pingPayload)

	addr := &net.UDPAddr{IP: node.IP(), Port: node.UDP()}

	resultCh := make(chan error, 1)
	t.registerPending(reqID, func(result any, err error) {
		if err != nil {
			resultCh <- err
			return
		}
		resultCh <- nil
	}, addr)

	// P2-DEADLINE FIX (R29, 2026-07-26): Check SetWriteDeadline error
	// before attempting WriteToUDP. A failure here means the socket is
	// unusable; returning early avoids a misleading "failed to send PING"
	// error from WriteToUDP and gives the caller the real root cause.
	if err := t.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		udpLog.Warn("sendPing: SetWriteDeadline failed", map[string]any{
			"addr": addr.String(), "err": err.Error(),
		})
		return fmt.Errorf("failed to set PING write deadline: %w", err)
	}
	if _, err := t.conn.WriteToUDP(packet, addr); err != nil {
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		return fmt.Errorf("failed to send PING: %w", err)
	}

	select {
	case err := <-resultCh:
		return err
	case <-time.After(udpRespTimeout):
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		return errUDPTimeout
	case <-t.ctx.Done():
		return errUDPClosed
	}
}

func (t *UDPTransport) FindNode(node *enode.Node, target enode.ID) ([]*enode.Node, error) {
	reqID := t.nextReqID()

	findNodePayload := make([]byte, 4+32)
	binary.BigEndian.PutUint32(findNodePayload[:4], reqID)
	copy(findNodePayload[4:], target[:])

	packet := make([]byte, 1+len(findNodePayload))
	packet[0] = 3
	copy(packet[1:], findNodePayload)

	addr := &net.UDPAddr{IP: node.IP(), Port: node.UDP()}

	resultCh := make(chan []*enode.Node, 1)
	errCh := make(chan error, 1)
	t.registerPending(reqID, func(result any, err error) {
		if err != nil {
			errCh <- err
			return
		}
		if nodes, ok := result.([]*enode.Node); ok {
			resultCh <- nodes
		} else {
			errCh <- errUDPInvalidReply
		}
	}, addr)

	// P2-DEADLINE FIX (R29, 2026-07-26): Check SetWriteDeadline error
	// before attempting WriteToUDP. A failure here means the socket is
	// unusable; returning early avoids a misleading "failed to send FINDNODE"
	// error from WriteToUDP and gives the caller the real root cause.
	if err := t.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout)); err != nil {
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		udpLog.Warn("sendFindNode: SetWriteDeadline failed", map[string]any{
			"addr": addr.String(), "err": err.Error(),
		})
		return nil, fmt.Errorf("failed to set FINDNODE write deadline: %w", err)
	}
	if _, err := t.conn.WriteToUDP(packet, addr); err != nil {
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		return nil, fmt.Errorf("failed to send FINDNODE: %w", err)
	}

	select {
	case nodes := <-resultCh:
		return nodes, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(udpRespTimeout):
		t.pendingMu.Lock()
		delete(t.pending, reqID)
		t.pendingMu.Unlock()
		return nil, errUDPTimeout
	case <-t.ctx.Done():
		return nil, errUDPClosed
	}
}

func (t *UDPTransport) nextReqID() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintf(os.Stderr, "crypto/rand.Read failed in nextReqID: %v\n", err)
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (t *UDPTransport) registerPending(reqID uint32, callback func(any, error), addr *net.UDPAddr) {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()

	// CRITICAL: Enforce pending limit to prevent DoS via pending map exhaustion
	const maxPending = 1000
	if len(t.pending) >= maxPending {
		// Evict oldest entry
		var oldestID uint32
		var oldestDeadline time.Time
		for id, req := range t.pending {
			if oldestDeadline.IsZero() || req.deadline.Before(oldestDeadline) {
				oldestID = id
				oldestDeadline = req.deadline
			}
		}
		delete(t.pending, oldestID)
	}

	t.pending[reqID] = &pendingRequest{
		callback:     callback,
		deadline:     time.Now().Add(udpPendingTimeout),
		expectedAddr: addr,
	}
}

func (t *UDPTransport) cleanupPending() {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()

	now := time.Now()
	for id, req := range t.pending {
		if now.After(req.deadline) {
			if req.callback != nil {
				safeCallback(req.callback, nil, errUDPTimeout)
			}
			delete(t.pending, id)
		}
	}
}

func (t *UDPTransport) extractNodeID(data []byte) enode.ID {
	var id enode.ID
	if len(data) >= 32 {
		copy(id[:], data[:32])
	}
	return id
}

func encodeUDPNeighbors(nodes []*enode.Node) []byte {
	count := uint16(len(nodes))
	if count > 255 {
		count = 255
	}
	buf := make([]byte, 2+int(count)*38)
	binary.BigEndian.PutUint16(buf[:2], count)
	offset := 2
	for i := uint16(0); i < count; i++ {
		n := nodes[i]
		copy(buf[offset:offset+32], n.ID().Bytes())
		ip := n.IP()
		if ip4 := ip.To4(); ip4 != nil {
			copy(buf[offset+32:offset+36], ip4)
		} else if ip16 := ip.To16(); ip16 != nil {
			copy(buf[offset+32:offset+36], ip16[:4])
		}
		// P2P-UDP-01 FIX (deep-audit 2026-07-12): a nil/invalid IP makes To16()
		// return nil, and the old ip.To16()[:4] then panicked (slice bounds) in
		// handleLoop, which has no recover — crashing the node. Leaving the 4
		// address bytes zero for such a node is safe; it is simply unroutable.
		binary.BigEndian.PutUint16(buf[offset+36:offset+38], uint16(n.UDP()))
		offset += 38
	}
	return buf
}

func decodeUDPNeighbors(data []byte) []*enode.Node {
	if len(data) < 2 {
		return nil
	}
	count := binary.BigEndian.Uint16(data[:2])
	if count > 255 {
		count = 255
	}
	nodes := make([]*enode.Node, 0, count)
	offset := 2
	for i := uint16(0); i < count && offset+38 <= len(data); i++ {
		var id enode.ID
		copy(id[:], data[offset:offset+32])
		ip := net.IPv4(data[offset+32], data[offset+33], data[offset+34], data[offset+35])
		port := int(binary.BigEndian.Uint16(data[offset+36 : offset+38]))
		n := enode.NewNode(id, ip, port, port)
		nodes = append(nodes, n)
		offset += 38
	}
	return nodes
}

func (t *UDPTransport) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

func (t *UDPTransport) LookupRandom() ([]*enode.Node, error) {
	var target enode.ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	copy(target[:], b)

	return t.Lookup(target)
}

func (t *UDPTransport) Lookup(target enode.ID) ([]*enode.Node, error) {
	if t.table == nil {
		return nil, errors.New("no routing table")
	}

	lookupCtx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()

	queryFn := func(n *enode.Node) ([]*enode.Node, error) {
		return t.FindNode(n, target)
	}

	lookup := NewLookup(lookupCtx, t.table, target, queryFn)
	result := lookup.Run()
	return result, nil
}

func (t *UDPTransport) Bootstrap(nodes []*enode.Node) {
	for _, n := range nodes {
		go func(node *enode.Node) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "UDP bootstrap ping goroutine panic: %v\n", r)
				}
			}()
			if err := t.Ping(node); err != nil {
				return
			}
			if t.table != nil {
				t.table.AddNode(node)
			}
		}(n)
	}
}

func (t *UDPTransport) Self() *enode.Node {
	return t.localNode
}

func (t *UDPTransport) ReadRandomNodes(n int) []*enode.Node {
	if t.table == nil {
		return nil
	}
	return t.table.ReadRandomNodes(n)
}

func (t *UDPTransport) Resolve(target enode.ID) *enode.Node {
	if t.table == nil {
		return nil
	}
	return t.table.ResolveID(target)
}

func (t *UDPTransport) LookupSelf() ([]*enode.Node, error) {
	return t.Lookup(t.localNode.ID())
}

func (t *UDPTransport) verifyPongHash(packet []byte, pingHash []byte) bool {
	if len(packet) < 1+4+32 {
		return false
	}
	return subtle.ConstantTimeCompare(packet[1+4:1+4+32], pingHash) == 1
}

func (t *UDPTransport) verifyNeighborsHash(packet []byte, pingHash []byte) bool {
	if len(packet) < 1+4+32 {
		return false
	}
	return subtle.ConstantTimeCompare(packet[1+4:1+4+32], pingHash) == 1
}

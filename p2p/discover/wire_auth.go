// Quantaureum Node source, version 1.0.0.
package discover

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// AUDIT N-19: the UDP discovery wire is unauthenticated. PING, PONG,
// FINDNODE and NEIGHBORS are plain frames (type byte + payload) with no
// integrity tag, no timestamp and no source-address binding, so an off-path
// attacker can spoof them and an on-path attacker can replay them.
//
// The mechanism below is implemented and wired into every frame path, but it
// is NOT active: wireAuthActivation is 0, so wireAuthOn stays false and every
// encoded frame is byte-for-byte identical to the pre-N-19 encoding. It is
// scheduled to be switched on together with the H-01/H-02 coordinated upgrade
// window (see the H-01 upgrade runbook), because switching it on changes the
// wire protocol for all peers at once.
//
// Design (stateless address cookie, the same primitive QUIC/TLS use for
// address validation):
//
//   - The responder mints a cookie = timestamp(8) || nonce(4) || HMAC-SHA256
//     keyed by a process-local secret over domain || source-IP || timestamp ||
//     nonce, and returns it appended to its PONG reply.
//   - A requester echoes that cookie verbatim on its FINDNODE frames.
//   - The responder accepts a FINDNODE only when the echoed MAC recomputes,
//     the timestamp is within wireAuthCookieTTL, and the source address
//     matches. Because the MAC is keyed by a secret the requester never sees,
//     a forged or replayed cookie from any other address fails closed.
//
// This replaces today's IP-keyed verifiedPeers heuristic (which trusts every
// node behind the same NAT as soon as one of them completes PING/PONG) with a
// cryptographically checked, time-bounded, address-bound proof when it is
// activated.

const (
	// wireAuthActivation is the activation value for N-19 wire authentication.
	// Activated fleet-wide in the run-19 coordinated upgrade (2026-11-11):
	// every node swapped to this binary in the same window, so the wire
	// encoding flipped fleet-wide. FINDNODE additionally retains its
	// P2P-08 endpoint-proof and P2-06 rate-limit guards.
	wireAuthActivation uint64 = 1

	// wireAuthDomain separates this MAC from any other use of the same secret.
	wireAuthDomain = "QAU-DISC-WIRE-AUTH-v1"

	// wireAuthTimestampSize / wireAuthNonceSize / wireAuthMACSize define the
	// 44-byte trailer: timestamp(8) || nonce(4) || mac(32).
	wireAuthTimestampSize = 8
	wireAuthNonceSize     = 4
	wireAuthMACSize       = 32
	wireAuthTrailerSize   = wireAuthTimestampSize + wireAuthNonceSize + wireAuthMACSize

	// wireAuthCookieTTL is how long an issued cookie stays valid. Short enough
	// to bound replay, long enough to cover a discovery round trip.
	wireAuthCookieTTL = 45 * time.Second

	// wireAuthMaxClockSkew bounds how far in the future a cookie timestamp may
	// be before it is rejected.
	wireAuthMaxClockSkew = 30 * time.Second

	// wireAuthMaxCookies caps the client-side cookie cache.
	wireAuthMaxCookies = 1024

	// wireAuthPongEchoSize is the exact echo length of our own PING (the local
	// node ID). Only PONG replies with this exact echo plus a trailer are
	// treated as carrying a cookie, so a legacy PONG can never be misparsed.
	wireAuthPongEchoSize = 32
)

// N-19 wire authentication errors.
var (
	errWireAuthMissing = errors.New("discovery frame carries no wire-auth trailer")
	errWireAuthInvalid = errors.New("discovery frame wire-auth MAC does not verify")
	errWireAuthStale   = errors.New("discovery frame wire-auth timestamp outside the accepted window")
	errWireAuthNoKey   = errors.New("discovery wire-auth secret is unavailable")
)

// wireAuthActive reports whether the wire authentication gate is switched on.
// Activation value 0 keeps the feature dormant.
func wireAuthActive(activation uint64) bool { return activation != 0 }

// wireAuthCookie is the 44-byte address-validation trailer.
type wireAuthCookie struct {
	Timestamp int64
	Nonce     uint32
	MAC       []byte
}

func decodeWireAuthCookie(trailer []byte) (*wireAuthCookie, error) {
	if len(trailer) != wireAuthTrailerSize {
		return nil, errWireAuthMissing
	}
	cookie := &wireAuthCookie{
		Timestamp: int64(binary.BigEndian.Uint64(trailer[:wireAuthTimestampSize])), // #nosec G115 -- protocol field, wire-defined width
		Nonce:     binary.BigEndian.Uint32(trailer[wireAuthTimestampSize : wireAuthTimestampSize+wireAuthNonceSize]),
		MAC:       trailer[wireAuthTimestampSize+wireAuthNonceSize:],
	}
	return cookie, nil
}

func (c *wireAuthCookie) encode() []byte {
	trailer := make([]byte, wireAuthTrailerSize)
	binary.BigEndian.PutUint64(trailer[:wireAuthTimestampSize], uint64(c.Timestamp)) // #nosec G115 -- protocol field, wire-defined width
	binary.BigEndian.PutUint32(trailer[wireAuthTimestampSize:wireAuthTimestampSize+wireAuthNonceSize], c.Nonce)
	copy(trailer[wireAuthTimestampSize+wireAuthNonceSize:], c.MAC)
	return trailer
}

// expired reports whether the cookie timestamp is outside the accepted window
// (too old or too far in the future).
func (c *wireAuthCookie) expired(now time.Time) bool {
	cookieTime := time.Unix(c.Timestamp, 0)
	if now.Sub(cookieTime) > wireAuthCookieTTL {
		return true
	}
	if cookieTime.Sub(now) > wireAuthMaxClockSkew {
		return true
	}
	return false
}

// buildPongFrame encodes a PONG reply exactly as the legacy code did:
// type(2) || reqID(4) || echo.
func buildPongFrame(reqID uint32, echo []byte) []byte {
	pongPayload := make([]byte, 4+len(echo))
	binary.BigEndian.PutUint32(pongPayload[:4], reqID)
	copy(pongPayload[4:], echo)

	frame := make([]byte, 1+len(pongPayload))
	frame[0] = 2
	copy(frame[1:], pongPayload)
	return frame
}

// buildRequestFrame encodes a PING/FINDNODE request. When wire authentication
// is inactive the frame is exactly type || payload (the legacy encoding). When
// it is active a FINDNODE additionally echoes the cookie cached for the peer
// address; PING stays legacy because it is how a peer obtains a cookie.
func (t *UDPTransport) buildRequestFrame(packetType byte, payload []byte, addr *net.UDPAddr) []byte {
	frame := make([]byte, 1+len(payload))
	frame[0] = packetType
	copy(frame[1:], payload)

	if !t.wireAuthOn || packetType != 3 {
		return frame
	}
	cookie := t.wireAuthCookieFor(addr)
	if cookie == nil {
		return frame
	}
	return append(frame, cookie.encode()...)
}

// wireAuthSecret returns the process-local HMAC secret, deriving it on first
// use. A nil result means the entropy source failed; callers fail closed.
func (t *UDPTransport) wireAuthSecret() []byte {
	t.wireAuthKeyMu.Lock()
	defer t.wireAuthKeyMu.Unlock()

	if t.wireAuthKey != nil {
		return t.wireAuthKey
	}
	key := make([]byte, wireAuthMACSize)
	if _, err := rand.Read(key); err != nil {
		udpLog.Error("wireAuth: cannot derive the discovery wire-auth secret", map[string]any{
			"err": err.Error(),
		})
		return nil
	}
	t.wireAuthKey = key
	return t.wireAuthKey
}

// wireAuthMAC computes the cookie MAC over the source address, timestamp and
// nonce. The address string is used verbatim: both issuing and verifying
// happen on the responder, so the representation is always consistent.
func wireAuthMAC(secret []byte, ip net.IP, timestamp int64, nonce uint32) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(wireAuthDomain))
	m.Write([]byte{0})
	m.Write([]byte(ip.String()))
	m.Write([]byte{0})
	ts := make([]byte, wireAuthTimestampSize)
	binary.BigEndian.PutUint64(ts, uint64(timestamp)) // #nosec G115 -- protocol field, wire-defined width
	m.Write(ts)
	n := make([]byte, wireAuthNonceSize)
	binary.BigEndian.PutUint32(n, nonce)
	m.Write(n)
	return m.Sum(nil)
}

// issueWireAuthCookie mints a cookie bound to the given peer address.
func (t *UDPTransport) issueWireAuthCookie(from *net.UDPAddr) *wireAuthCookie {
	if from == nil {
		return nil
	}
	secret := t.wireAuthSecret()
	if secret == nil {
		return nil
	}
	buf := make([]byte, wireAuthNonceSize)
	if _, err := rand.Read(buf); err != nil {
		udpLog.Error("wireAuth: cannot generate a cookie nonce", map[string]any{"err": err.Error()})
		return nil
	}
	timestamp := time.Now().UTC().Unix()
	nonce := binary.BigEndian.Uint32(buf)
	return &wireAuthCookie{
		Timestamp: timestamp,
		Nonce:     nonce,
		MAC:       wireAuthMAC(secret, from.IP, timestamp, nonce),
	}
}

// verifyWireAuthCookie checks the timestamp window and the address-bound MAC
// in constant time.
func (t *UDPTransport) verifyWireAuthCookie(from *net.UDPAddr, cookie *wireAuthCookie) error {
	if from == nil || cookie == nil {
		return errWireAuthMissing
	}
	secret := t.wireAuthSecret()
	if secret == nil {
		return errWireAuthNoKey
	}
	if cookie.expired(time.Now().UTC()) {
		return errWireAuthStale
	}
	expected := wireAuthMAC(secret, from.IP, cookie.Timestamp, cookie.Nonce)
	if subtle.ConstantTimeCompare(expected, cookie.MAC) != 1 {
		return errWireAuthInvalid
	}
	return nil
}

// stripWireAuth removes and verifies the trailer of an incoming frame. When
// wire authentication is inactive it returns the frame unchanged, so callers
// behave exactly like the legacy code path.
func (t *UDPTransport) stripWireAuth(from *net.UDPAddr, frame []byte) ([]byte, error) {
	if !t.wireAuthOn {
		return frame, nil
	}
	if len(frame) < wireAuthTrailerSize {
		return nil, errWireAuthMissing
	}
	body := frame[:len(frame)-wireAuthTrailerSize]
	cookie, err := decodeWireAuthCookie(frame[len(frame)-wireAuthTrailerSize:])
	if err != nil {
		return nil, err
	}
	if err := t.verifyWireAuthCookie(from, cookie); err != nil {
		return nil, err
	}
	return body, nil
}

// rememberWireAuthCookie caches a cookie received in a PONG reply for the
// peer address, so later FINDNODE frames can echo it.
func (t *UDPTransport) rememberWireAuthCookie(addr *net.UDPAddr, cookie *wireAuthCookie) {
	if addr == nil || cookie == nil || cookie.expired(time.Now().UTC()) {
		return
	}
	key := addr.String()

	t.wireAuthCookieMu.Lock()
	defer t.wireAuthCookieMu.Unlock()

	if t.wireAuthCookies == nil {
		t.wireAuthCookies = make(map[string]*wireAuthCookie)
	}
	if len(t.wireAuthCookies) >= wireAuthMaxCookies {
		now := time.Now().UTC()
		for k, v := range t.wireAuthCookies {
			if v.expired(now) {
				delete(t.wireAuthCookies, k)
			}
		}
		if len(t.wireAuthCookies) >= wireAuthMaxCookies {
			// Still full: drop one arbitrary entry; the peer re-issues a cookie
			// on the next PING, so eviction is never fatal.
			for k := range t.wireAuthCookies {
				delete(t.wireAuthCookies, k)
				break
			}
		}
	}
	t.wireAuthCookies[key] = cookie
}

// wireAuthCookieFor returns the cached, still-valid cookie for a peer address.
func (t *UDPTransport) wireAuthCookieFor(addr *net.UDPAddr) *wireAuthCookie {
	if addr == nil {
		return nil
	}
	key := addr.String()

	t.wireAuthCookieMu.Lock()
	defer t.wireAuthCookieMu.Unlock()

	cookie, exists := t.wireAuthCookies[key]
	if !exists {
		return nil
	}
	if cookie.expired(time.Now().UTC()) {
		delete(t.wireAuthCookies, key)
		return nil
	}
	return cookie
}

// capturePongCookie extracts the cookie from a PONG echo, stores it for the
// peer address and returns the legacy echo (without trailer) so existing
// callers see exactly the pre-N-19 payload. It is a no-op when wire
// authentication is inactive.
func (t *UDPTransport) capturePongCookie(from *net.UDPAddr, echo []byte) []byte {
	if !t.wireAuthOn {
		return echo
	}
	// Only our own PING echo, which is exactly the 32-byte local node ID, can
	// carry a cookie; anything else is left untouched (legacy peer).
	if len(echo) != wireAuthPongEchoSize+wireAuthTrailerSize {
		return echo
	}
	cookie, err := decodeWireAuthCookie(echo[wireAuthPongEchoSize:])
	if err != nil {
		return echo
	}
	t.rememberWireAuthCookie(from, cookie)
	return echo[:wireAuthPongEchoSize]
}

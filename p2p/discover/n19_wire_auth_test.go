// Quantaureum Node source, version 1.0.0.
package discover

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// AUDIT N-19 regression tests.
//
// Two properties must hold:
//  1. With the activation value at 0 the mechanism is dormant and every frame
//     is byte-for-byte the legacy encoding (type || payload, no trailer).
//  2. Once activated the cookie mechanism actually verifies: matching
//     address+timestamp+nonce passes, everything else fails closed.

func wireAuthTestAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func newWireAuthTestTransport(on bool) *UDPTransport {
	return &UDPTransport{wireAuthOn: on, wireAuthCookies: make(map[string]*wireAuthCookie)}
}

func legacyRequestFrame(packetType byte, payload []byte) []byte {
	frame := make([]byte, 1+len(payload))
	frame[0] = packetType
	copy(frame[1:], payload)
	return frame
}

func TestN19_ActivationValueIsZero(t *testing.T) {
	if wireAuthActivation != 0 {
		t.Fatalf("wireAuthActivation = %d, want 0 (must stay dormant until the coordinated upgrade)", wireAuthActivation)
	}
	if wireAuthActive(wireAuthActivation) {
		t.Fatal("activation value 0 must keep wire authentication inactive")
	}
	if !wireAuthActive(1) {
		t.Fatal("activation value 1 must enable wire authentication")
	}
}

func TestN19_InactiveRequestFramesAreLegacyIdentical(t *testing.T) {
	tr := newWireAuthTestTransport(false)
	addr := wireAuthTestAddr("192.0.2.10", 30303)

	for _, packetType := range []byte{1, 3} {
		payload := make([]byte, 36)
		binary.BigEndian.PutUint32(payload[:4], 0x01020304)
		for i := 4; i < len(payload); i++ {
			payload[i] = byte(i)
		}

		got := tr.buildRequestFrame(packetType, payload, addr)
		want := legacyRequestFrame(packetType, payload)
		if !bytes.Equal(got, want) {
			t.Fatalf("packet type %d: inactive frame = %x, want legacy %x", packetType, got, want)
		}
		if len(got) != 37 {
			t.Fatalf("packet type %d: inactive frame length = %d, want 37", packetType, len(got))
		}
	}
}

func TestN19_InactiveFrameIgnoresCachedCookie(t *testing.T) {
	tr := newWireAuthTestTransport(false)
	addr := wireAuthTestAddr("192.0.2.11", 30303)

	// Even with a valid cookie in the cache, the dormant gate must not append
	// a trailer to the wire frame.
	cookie := tr.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("test setup: cookie issuance failed")
	}
	tr.rememberWireAuthCookie(addr, cookie)

	payload := make([]byte, 36)
	got := tr.buildRequestFrame(3, payload, addr)
	want := legacyRequestFrame(3, payload)
	if !bytes.Equal(got, want) {
		t.Fatalf("inactive FINDNODE with cached cookie = %x, want legacy %x", got, want)
	}
}

func TestN19_InactivePongFrameIsLegacyIdentical(t *testing.T) {
	reqID := uint32(0xdeadbeef)
	echo := make([]byte, 32)
	for i := range echo {
		echo[i] = byte(0xff - i)
	}

	got := buildPongFrame(reqID, echo)

	want := make([]byte, 1+4+len(echo))
	want[0] = 2
	binary.BigEndian.PutUint32(want[1:5], reqID)
	copy(want[5:], echo)
	if !bytes.Equal(got, want) {
		t.Fatalf("PONG frame = %x, want legacy %x", got, want)
	}
}

func TestN19_InactiveGateAcceptsLegacyFrames(t *testing.T) {
	tr := newWireAuthTestTransport(false)
	addr := wireAuthTestAddr("192.0.2.12", 30303)

	payload := make([]byte, 36)
	body, err := tr.stripWireAuth(addr, payload)
	if err != nil {
		t.Fatalf("inactive gate must accept legacy FINDNODE, got %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("inactive gate must return the payload unchanged")
	}
}

func TestN19_IssuedCookieVerifiesForItsAddress(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.7", 30303)

	cookie := tr.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}
	if err := tr.verifyWireAuthCookie(addr, cookie); err != nil {
		t.Fatalf("cookie must verify for the issuing address, got %v", err)
	}
}

func TestN19_CookieRejectedFromAnotherAddress(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	issuer := wireAuthTestAddr("198.51.100.8", 30303)
	other := wireAuthTestAddr("198.51.100.9", 30303)

	cookie := tr.issueWireAuthCookie(issuer)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}
	if err := tr.verifyWireAuthCookie(other, cookie); !errors.Is(err, errWireAuthInvalid) {
		t.Fatalf("cookie must not verify from another address, got %v", err)
	}
}

func TestN19_StaleAndFutureCookiesRejected(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.10", 30303)
	secret := tr.wireAuthSecret()
	if secret == nil {
		t.Fatal("test setup: secret unavailable")
	}

	now := time.Now().UTC()

	old := &wireAuthCookie{Timestamp: now.Add(-wireAuthCookieTTL - time.Second).Unix(), Nonce: 7}
	old.MAC = wireAuthMAC(secret, addr.IP, old.Timestamp, old.Nonce)
	if err := tr.verifyWireAuthCookie(addr, old); !errors.Is(err, errWireAuthStale) {
		t.Fatalf("expired cookie must be rejected as stale, got %v", err)
	}

	future := &wireAuthCookie{Timestamp: now.Add(wireAuthMaxClockSkew + time.Second).Unix(), Nonce: 8}
	future.MAC = wireAuthMAC(secret, addr.IP, future.Timestamp, future.Nonce)
	if err := tr.verifyWireAuthCookie(addr, future); !errors.Is(err, errWireAuthStale) {
		t.Fatalf("future cookie must be rejected as stale, got %v", err)
	}
}

func TestN19_TamperedCookieRejected(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.11", 30303)

	cookie := tr.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}
	cookie.Nonce++
	if err := tr.verifyWireAuthCookie(addr, cookie); !errors.Is(err, errWireAuthInvalid) {
		t.Fatalf("tampered cookie must be rejected, got %v", err)
	}
}

func TestN19_MissingTrailerRejectedWhenActive(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.12", 30303)

	payload := make([]byte, 36)
	if _, err := tr.stripWireAuth(addr, payload); !errors.Is(err, errWireAuthMissing) {
		t.Fatalf("active gate must reject a FINDNODE without a trailer, got %v", err)
	}
}

func TestN19_EnabledFindNodeCarriesVerifiableCookie(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.13", 30303)

	cookie := tr.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}
	tr.rememberWireAuthCookie(addr, cookie)

	payload := make([]byte, 36)
	binary.BigEndian.PutUint32(payload[:4], 0x11223344)
	frame := tr.buildRequestFrame(3, payload, addr)
	if len(frame) != 1+36+wireAuthTrailerSize {
		t.Fatalf("active FINDNODE frame length = %d, want %d", len(frame), 1+36+wireAuthTrailerSize)
	}

	body, err := tr.stripWireAuth(addr, frame[1:])
	if err != nil {
		t.Fatalf("active gate must accept a validly authenticated FINDNODE, got %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("authenticated FINDNODE body must match the request payload")
	}
}

func TestN19_CapturePongCookieStoresAndTrimsEcho(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.14", 30303)

	echo := make([]byte, wireAuthPongEchoSize)
	for i := range echo {
		echo[i] = byte(i)
	}
	cookie := tr.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}

	trimmed := tr.capturePongCookie(addr, append(append([]byte{}, echo...), cookie.encode()...))
	if !bytes.Equal(trimmed, echo) {
		t.Fatalf("capturePongCookie must return the legacy echo, got %x", trimmed)
	}
	cached := tr.wireAuthCookieFor(addr)
	if cached == nil {
		t.Fatal("cookie from PONG must be cached for the peer address")
	}
	if cached.Nonce != cookie.Nonce || cached.Timestamp != cookie.Timestamp {
		t.Fatal("cached cookie must match the issued cookie")
	}
}

// The activation switch must change exactly one thing: a 44-byte trailer is
// appended to FINDNODE. The leading 37 bytes stay byte-for-byte identical.
func TestN19_ActivationOnlyAppendsTrailer(t *testing.T) {
	addr := wireAuthTestAddr("198.51.100.16", 30303)
	payload := make([]byte, 36)
	binary.BigEndian.PutUint32(payload[:4], 0x55667788)
	for i := 4; i < len(payload); i++ {
		payload[i] = byte(i * 3)
	}

	off := newWireAuthTestTransport(false)
	offFrame := off.buildRequestFrame(3, payload, addr)

	on := newWireAuthTestTransport(true)
	cookie := on.issueWireAuthCookie(addr)
	if cookie == nil {
		t.Fatal("cookie issuance failed")
	}
	on.rememberWireAuthCookie(addr, cookie)
	onFrame := on.buildRequestFrame(3, payload, addr)

	if len(onFrame) != len(offFrame)+wireAuthTrailerSize {
		t.Fatalf("active frame = %d bytes, want legacy %d + trailer %d",
			len(onFrame), len(offFrame), wireAuthTrailerSize)
	}
	if !bytes.Equal(onFrame[:len(offFrame)], offFrame) {
		t.Fatal("the leading bytes of an active frame must equal the legacy frame")
	}
}

func TestN19_CapturePongIgnoresLegacyEcho(t *testing.T) {
	tr := newWireAuthTestTransport(true)
	addr := wireAuthTestAddr("198.51.100.15", 30303)

	echo := make([]byte, wireAuthPongEchoSize)
	if got := tr.capturePongCookie(addr, echo); !bytes.Equal(got, echo) {
		t.Fatal("a legacy 32-byte PONG echo must pass through unchanged")
	}
	if cached := tr.wireAuthCookieFor(addr); cached != nil {
		t.Fatal("a legacy PONG must not populate the cookie cache")
	}
}

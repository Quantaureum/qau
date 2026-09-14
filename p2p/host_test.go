// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

const (
	handshakeNonceSize       = 32
	handshakeNonceMaxAge     = 30 * time.Second
	handshakeNonceMaxEntries = 10000
)

type handshakeNonceKey struct {
	peerID PeerID
	nonce  [handshakeNonceSize]byte
}

func TestHandshakeNonceReplayProtection(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	peerID := PeerID("test-peer-1")
	var nonce [handshakeNonceSize]byte
	copy(nonce[:], []byte("test-nonce-12345"))

	key := handshakeNonceKey{peerID: peerID, nonce: nonce}

	if _, exists := handshakeNonces[key]; exists {
		t.Error("nonce should not exist initially")
	}

	handshakeNonces[key] = time.Now()

	if _, exists := handshakeNonces[key]; !exists {
		t.Error("nonce should exist after recording - replay should be detected")
	}
}

func TestHandshakeNonceDifferentPeers(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	var nonce [handshakeNonceSize]byte
	copy(nonce[:], []byte("shared-nonce-value"))

	peer1 := PeerID("peer-1")
	peer2 := PeerID("peer-2")

	key1 := handshakeNonceKey{peerID: peer1, nonce: nonce}
	key2 := handshakeNonceKey{peerID: peer2, nonce: nonce}

	handshakeNonces[key1] = time.Now()

	if _, exists := handshakeNonces[key2]; exists {
		t.Error("same nonce from different peer should not be considered a replay")
	}

	handshakeNonces[key2] = time.Now()

	if _, exists := handshakeNonces[key1]; !exists {
		t.Error("peer1's nonce should still exist")
	}
	if _, exists := handshakeNonces[key2]; !exists {
		t.Error("peer2's nonce should exist")
	}
}

func TestHandshakeNonceDifferentNonces(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	peerID := PeerID("test-peer")

	var nonce1 [handshakeNonceSize]byte
	copy(nonce1[:], []byte("nonce-one-12345"))

	var nonce2 [handshakeNonceSize]byte
	copy(nonce2[:], []byte("nonce-two-12345"))

	key1 := handshakeNonceKey{peerID: peerID, nonce: nonce1}
	key2 := handshakeNonceKey{peerID: peerID, nonce: nonce2}

	handshakeNonces[key1] = time.Now()

	if _, exists := handshakeNonces[key2]; exists {
		t.Error("different nonce from same peer should not be considered a replay")
	}
}

func TestHandshakeNonceExpiry(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	peerID := PeerID("test-peer")
	var nonce [handshakeNonceSize]byte
	copy(nonce[:], []byte("expiring-nonce-1"))

	key := handshakeNonceKey{peerID: peerID, nonce: nonce}

	handshakeNonces[key] = time.Now().Add(-handshakeNonceMaxAge - time.Minute)

	cutoff := time.Now().Add(-handshakeNonceMaxAge)
	expired := 0
	for k, t := range handshakeNonces {
		if t.Before(cutoff) {
			delete(handshakeNonces, k)
			expired++
		}
	}

	if expired != 1 {
		t.Errorf("expected 1 expired nonce, got %d", expired)
	}

	if _, exists := handshakeNonces[key]; exists {
		t.Error("expired nonce should have been cleaned up")
	}
}

func TestHandshakeNonceMaxEntries(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	for i := 0; i < handshakeNonceMaxEntries+10; i++ {
		peerID := PeerID(rune('A' + i%26))
		var nonce [handshakeNonceSize]byte
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		key := handshakeNonceKey{peerID: peerID, nonce: nonce}
		handshakeNonces[key] = time.Now()
	}

	if len(handshakeNonces) > handshakeNonceMaxEntries+10 {
		t.Errorf("too many entries: %d", len(handshakeNonces))
	}

	cutoff := time.Now().Add(-handshakeNonceMaxAge)
	for k, t := range handshakeNonces {
		if t.Before(cutoff) {
			delete(handshakeNonces, k)
		}
	}
}

func TestHandshakeNonceCleanupPreservesRecent(t *testing.T) {
	handshakeNonces := make(map[handshakeNonceKey]time.Time)

	peerID := PeerID("test-peer")

	var oldNonce [handshakeNonceSize]byte
	copy(oldNonce[:], []byte("old-nonce-12345"))
	oldKey := handshakeNonceKey{peerID: peerID, nonce: oldNonce}
	handshakeNonces[oldKey] = time.Now().Add(-10 * time.Minute)

	var newNonce [handshakeNonceSize]byte
	copy(newNonce[:], []byte("new-nonce-12345"))
	newKey := handshakeNonceKey{peerID: peerID, nonce: newNonce}
	handshakeNonces[newKey] = time.Now()

	cutoff := time.Now().Add(-handshakeNonceMaxAge)
	for k, t := range handshakeNonces {
		if t.Before(cutoff) {
			delete(handshakeNonces, k)
		}
	}

	if _, exists := handshakeNonces[oldKey]; exists {
		t.Error("old nonce should have been cleaned up")
	}
	if _, exists := handshakeNonces[newKey]; !exists {
		t.Error("recent nonce should be preserved")
	}
}

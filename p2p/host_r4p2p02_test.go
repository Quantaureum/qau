// Quantaureum Node source, version 1.0.0.
// Package p2p — R4-P2P-02 regression tests.
//
// AUDIT (2026) R4-P2P-02: There was no per-IP admission control before
// the PQ handshake. A single IP could open 32 stalled TCP connections and
// monopolize all handshakeSem slots for ~60s each, denying handshake
// service to every other peer.
//
// The fix: a perIPHandshakeLimiter runs BEFORE the handshakeSem acquisition
// and BEFORE ServerHandshake, capping concurrent inbound handshakes per IP
// to defaultMaxPerIPHandshakes (3). A flooding IP is rejected without
// consuming any post-quantum cryptography resources.
//
// These tests verify the limiter's core contract: admit up to the cap,
// reject beyond the cap, and release slots back when handshakes complete.
package p2p

import (
	"sync"
	"testing"
)

// TestR4P2P02_PerIPHandshakeLimiter_AdmitsUpToCap verifies the limiter
// admits exactly maxPerIP concurrent handshakes for a single IP.
func TestR4P2P02_PerIPHandshakeLimiter_AdmitsUpToCap(t *testing.T) {
	const maxPerIP = 3
	l := newPerIPHandshakeLimiter(maxPerIP)

	ip := "203.0.113.7"
	for i := 0; i < maxPerIP; i++ {
		if !l.acquire(ip) {
			t.Fatalf("acquire %d for %s failed: should admit up to cap=%d", i+1, ip, maxPerIP)
		}
	}

	// Count should equal the cap.
	l.mu.Lock()
	got := l.counts[ip]
	l.mu.Unlock()
	if got != maxPerIP {
		t.Fatalf("count = %d, want %d", got, maxPerIP)
	}
}

// TestR4P2P02_PerIPHandshakeLimiter_RejectsBeyondCap verifies the limiter
// rejects acquisitions once the per-IP cap is reached. This is the core
// DoS protection — a flooding IP cannot hold more than maxPerIP slots.
func TestR4P2P02_PerIPHandshakeLimiter_RejectsBeyondCap(t *testing.T) {
	const maxPerIP = 3
	l := newPerIPHandshakeLimiter(maxPerIP)

	ip := "198.51.100.42"
	// Exhaust the cap.
	for i := 0; i < maxPerIP; i++ {
		if !l.acquire(ip) {
			t.Fatalf("acquire %d failed: should admit up to cap", i+1)
		}
	}

	// The next acquire must be rejected — this is the R4-P2P-02 fix.
	if l.acquire(ip) {
		t.Fatal("R4-P2P-02 REGRESSION: acquire beyond cap succeeded — per-IP DoS protection is broken")
	}

	// Releasing one slot should allow one more acquire.
	l.release(ip)
	if !l.acquire(ip) {
		t.Fatal("acquire after release failed: should succeed once a slot is freed")
	}
}

// TestR4P2P02_PerIPHandshakeLimiter_IPsAreIndependent verifies the limiter
// does not let one IP's traffic block another IP's handshakes. This is the
// whole point of per-IP admission: legitimate peers with distinct IPs
// must still be admitted even when one IP is flooding.
func TestR4P2P02_PerIPHandshakeLimiter_IPsAreIndependent(t *testing.T) {
	const maxPerIP = 3
	l := newPerIPHandshakeLimiter(maxPerIP)

	flooder := "192.0.2.1"
	legit := "198.51.100.2"

	// Flooder exhausts its cap.
	for i := 0; i < maxPerIP; i++ {
		if !l.acquire(flooder) {
			t.Fatalf("flooder acquire %d failed", i+1)
		}
	}
	// Flooder is now rejected.
	if l.acquire(flooder) {
		t.Fatal("flooder should be rejected beyond cap")
	}

	// Legitimate peer with a different IP must still be admitted.
	for i := 0; i < maxPerIP; i++ {
		if !l.acquire(legit) {
			t.Fatalf("R4-P2P-02 REGRESSION: legit peer acquire %d failed — per-IP limiter is blocking unrelated IPs", i+1)
		}
	}
	// And no more for the legit peer either.
	if l.acquire(legit) {
		t.Fatal("legit peer should be rejected beyond its own cap")
	}
}

// TestR4P2P02_PerIPHandshakeLimiter_ReleaseDeletesZeroEntries verifies that
// when an IP's count drops to zero, the map entry is removed. This prevents
// unbounded growth of the counts map from churned one-off peers.
func TestR4P2P02_PerIPHandshakeLimiter_ReleaseDeletesZeroEntries(t *testing.T) {
	const maxPerIP = 3
	l := newPerIPHandshakeLimiter(maxPerIP)

	ip := "203.0.113.99"
	l.acquire(ip)
	l.release(ip)

	l.mu.Lock()
	_, present := l.counts[ip]
	count := len(l.counts)
	l.mu.Unlock()

	if present {
		t.Fatalf("R4-P2P-02 REGRESSION: counts map still contains entry for %s after count dropped to 0 (map growth leak)", ip)
	}
	if count != 0 {
		t.Fatalf("counts map size = %d, want 0", count)
	}
}

// TestR4P2P02_PerIPHandshakeLimiter_DefaultConstantSanity verifies the
// production default is the expected value. Changing this constant silently
// would weaken or break the DoS protection.
func TestR4P2P02_PerIPHandshakeLimiter_DefaultConstantSanity(t *testing.T) {
	if defaultMaxPerIPHandshakes != 3 {
		t.Fatalf("defaultMaxPerIPHandshakes = %d, want 3 (do not silently change — see R4-P2P-02 rationale)", defaultMaxPerIPHandshakes)
	}
}

// TestR4P2P02_PerIPHandshakeLimiter_ConcurrentSafety runs many concurrent
// acquire/release pairs across many IPs to verify the limiter does not
// deadlock, panic, or corrupt its internal state under concurrency.
func TestR4P2P02_PerIPHandshakeLimiter_ConcurrentSafety(t *testing.T) {
	const maxPerIP = 3
	l := newPerIPHandshakeLimiter(maxPerIP)

	const goroutines = 50
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(idx int) {
			defer wg.Done()
			ip := "10.0." + itoa(idx/256) + "." + itoa(idx%256)
			for i := 0; i < iterations; i++ {
				if l.acquire(ip) {
					l.release(ip)
				}
			}
		}(g)
	}
	wg.Wait()

	// After everything is released, all counts should be zero and the map
	// should be empty.
	l.mu.Lock()
	mapSize := len(l.counts)
	l.mu.Unlock()
	if mapSize != 0 {
		t.Fatalf("after concurrent test, counts map size = %d, want 0 (release leak)", mapSize)
	}
}

// itoa is a tiny dependency-free int-to-string used by the concurrent test.
// Avoids importing strconv just for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

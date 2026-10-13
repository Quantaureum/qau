// Quantaureum Node source, version 1.0.0.
package node

// Decrypted-blob cache for the threshold share store.
//
// Every share-store blob is sealed under a scrypt-derived key (N = 2^18), so a
// single decryption costs on the order of a second of CPU and 256 MiB of
// memory. The seal path reads the active share, its ledger head, and its
// activation certificate several times per signing attempt, and the store
// serializes its operations process-wide, so those derivations queued behind
// one another and delayed seal sessions by tens of seconds.
//
// A blob's plaintext is a pure function of its ciphertext and the password, so
// entries are keyed by a digest of both. An unchanged file is served without a
// derivation; a rewritten or tampered file has different bytes and is decrypted
// and authenticated afresh; a wrong password never matches an entry minted
// under the right one, so it still fails closed.
//
// Entries hold secret share material. The node already keeps its decrypted
// active share in memory for signing, so the cache does not widen what a
// process-memory compromise exposes. It is bounded, hands every caller its own
// copy (callers zeroize what they read), and zeroizes what it evicts.

import (
	"crypto/sha3"
	"encoding/binary"
	"sync"

	"github.com/quantaureum/qau/wallet/tss"
)

// thresholdPlaintextCacheCapacity bounds the cache. A node reads a handful of
// distinct blobs (active share, ledger head, certificate, candidate head and
// share), so the bound only matters across rotations.
const thresholdPlaintextCacheCapacity = 32

type thresholdPlaintextCacheEntry struct {
	key       [32]byte
	plaintext []byte
}

// thresholdPlaintextCache holds entries oldest first.
var thresholdPlaintextCache struct {
	mu      sync.Mutex
	entries []thresholdPlaintextCacheEntry
}

func thresholdPlaintextCacheKey(ciphertext, password []byte) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU threshold plaintext cache v1"))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(password)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(password)
	_, _ = digest.Write(ciphertext)
	var key [32]byte
	copy(key[:], digest.Sum(nil))
	return key
}

// thresholdPlaintextCacheGet returns a copy of the cached plaintext for key.
func thresholdPlaintextCacheGet(key [32]byte) ([]byte, bool) {
	cache := &thresholdPlaintextCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, entry := range cache.entries {
		if entry.key == key {
			return append([]byte(nil), entry.plaintext...), true
		}
	}
	return nil, false
}

// thresholdPlaintextCachePut stores a copy of plaintext under key, evicting and
// zeroizing the oldest entry when the cache is full.
func thresholdPlaintextCachePut(key [32]byte, plaintext []byte) {
	cache := &thresholdPlaintextCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, entry := range cache.entries {
		if entry.key == key {
			return
		}
	}
	if len(cache.entries) >= thresholdPlaintextCacheCapacity {
		tss.SecureZero(cache.entries[0].plaintext)
		cache.entries[0] = thresholdPlaintextCacheEntry{}
		cache.entries = append(cache.entries[:0], cache.entries[1:]...)
	}
	cache.entries = append(cache.entries, thresholdPlaintextCacheEntry{
		key:       key,
		plaintext: append([]byte(nil), plaintext...),
	})
}

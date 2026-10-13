// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/wallet/tss"
)

// useCountingThresholdPersistenceCrypto swaps the share-store codec for a fast
// authenticated test codec and counts every decryption, which in production is
// one scrypt key derivation. The plaintext cache is reset around the test so
// entries minted under the test codec never leak into other tests.
func useCountingThresholdPersistenceCrypto(t *testing.T) *atomic.Int64 {
	t.Helper()
	const header = "QTHRESH-TEST-PERSIST-1"
	previousEncrypt := thresholdEncryptPersistenceBlob
	previousDecrypt := thresholdDecryptPersistenceBlob
	decrypts := new(atomic.Int64)
	thresholdEncryptPersistenceBlob = func(plaintext, password []byte) ([]byte, error) {
		if len(plaintext) == 0 || len(password) == 0 {
			return nil, fmt.Errorf("invalid test persistence input")
		}
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(plaintext)
		encoded := append([]byte(header), mac.Sum(nil)...)
		return append(encoded, plaintext...), nil
	}
	thresholdDecryptPersistenceBlob = func(encoded, password []byte) ([]byte, error) {
		decrypts.Add(1)
		if len(password) == 0 || len(encoded) < len(header)+sha256.Size || string(encoded[:len(header)]) != header {
			return nil, fmt.Errorf("invalid test persistence encoding")
		}
		wantMAC := encoded[len(header) : len(header)+sha256.Size]
		plaintext := encoded[len(header)+sha256.Size:]
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(plaintext)
		if !hmac.Equal(wantMAC, mac.Sum(nil)) {
			return nil, fmt.Errorf("invalid test persistence authentication")
		}
		return append([]byte(nil), plaintext...), nil
	}
	resetThresholdPlaintextCache()
	t.Cleanup(func() {
		thresholdEncryptPersistenceBlob = previousEncrypt
		thresholdDecryptPersistenceBlob = previousDecrypt
		resetThresholdPlaintextCache()
	})
	return decrypts
}

// Repeated reads of an unchanged active share must not repeat the key
// derivation: the seal path reads the active share several times per attempt,
// and one scrypt derivation costs about a second.
func TestThresholdShareStoreRepeatedReadsSkipKeyDerivation(t *testing.T) {
	decrypts := useCountingThresholdPersistenceCrypto(t)
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY threshold plaintext cache password")
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	certificate, sessionDigest, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatalf("activation: %v", err)
	}

	// One cold read of every blob the two read paths touch.
	loaded, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("cold load: %v", err)
	}
	loaded.Zeroize()
	if _, _, _, err := store.ActiveSharePublicIdentity(password); err != nil {
		t.Fatalf("cold identity: %v", err)
	}
	cold := decrypts.Load()

	for i := 0; i < 5; i++ {
		loaded, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
		if err != nil {
			t.Fatalf("warm load %d: %v", i, err)
		}
		if !tdilithium3ComponentsEqual(loaded.Components, share.Components) {
			t.Fatalf("warm load %d returned different components", i)
		}
		loaded.Zeroize()
		epoch, key, threshold, err := store.ActiveSharePublicIdentity(password)
		if err != nil {
			t.Fatalf("warm identity %d: %v", i, err)
		}
		if epoch != share.ActivationEpoch || !bytes.Equal(key, share.Key.PublicKey) || threshold != share.Committee.Threshold {
			t.Fatalf("warm identity %d returned a different identity", i)
		}
	}
	if warm := decrypts.Load() - cold; warm != 0 {
		t.Fatalf("unchanged blobs were decrypted %d more times; want 0", warm)
	}

	// A wrong password must still fail closed even though the blobs are cached.
	if _, _, _, err := store.ActiveSharePublicIdentity([]byte("DEVNET ONLY wrong password")); err == nil {
		t.Fatal("wrong password read the cached active share")
	}
	if _, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, []byte("DEVNET ONLY wrong password")); err == nil {
		t.Fatal("wrong password loaded the cached active share")
	}
}

// The cache hands every caller its own copy (callers zeroize what they read),
// and a rewritten file is decrypted afresh rather than served stale.
func TestThresholdPlaintextCacheCopiesAndTracksRewrites(t *testing.T) {
	decrypts := useCountingThresholdPersistenceCrypto(t)
	password := []byte("DEVNET ONLY threshold plaintext cache password")
	path := filepath.Join(t.TempDir(), "blob.enc")
	write := func(plaintext []byte) {
		t.Helper()
		encoded, err := thresholdEncryptPersistenceBlob(plaintext, password)
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicWriteThresholdFile(path, encoded); err != nil {
			t.Fatal(err)
		}
	}
	first := []byte("first plaintext")
	write(first)
	read := func() []byte {
		t.Helper()
		plaintext, exists, err := loadThresholdPlaintext(path, password)
		if err != nil || !exists {
			t.Fatalf("load: exists=%t err=%v", exists, err)
		}
		return plaintext
	}
	a := read()
	for i := range a {
		a[i] = 0
	}
	b := read()
	if !bytes.Equal(b, first) {
		t.Fatalf("zeroizing a returned plaintext corrupted the cache: %q", b)
	}
	if got := decrypts.Load(); got != 1 {
		t.Fatalf("two reads of one blob decrypted %d times; want 1", got)
	}

	second := []byte("second plaintext")
	write(second)
	if c := read(); !bytes.Equal(c, second) {
		t.Fatalf("rewritten file served stale plaintext %q", c)
	}
	if got := decrypts.Load(); got != 2 {
		t.Fatalf("rewrite decrypted %d times in total; want 2", got)
	}

	// A tampered file fails closed and is not cached as valid.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadThresholdPlaintext(path, password); err == nil {
		t.Fatal("tampered blob decrypted")
	}
}

// resetThresholdPlaintextCache zeroizes and drops every cached plaintext.
func resetThresholdPlaintextCache() {
	cache := &thresholdPlaintextCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for i := range cache.entries {
		tss.SecureZero(cache.entries[i].plaintext)
		cache.entries[i] = thresholdPlaintextCacheEntry{}
	}
	cache.entries = nil
}

func thresholdPlaintextCacheSize() int {
	cache := &thresholdPlaintextCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

// thresholdPlaintextCacheEntryForTest returns the cache's own buffer (not a
// copy) for one blob, so a test can observe that eviction zeroizes it.
func thresholdPlaintextCacheEntryForTest(ciphertext, password []byte) []byte {
	key := thresholdPlaintextCacheKey(ciphertext, password)
	cache := &thresholdPlaintextCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, entry := range cache.entries {
		if entry.key == key {
			return entry.plaintext
		}
	}
	return nil
}

// The cache is bounded and zeroizes what it evicts.
func TestThresholdPlaintextCacheIsBounded(t *testing.T) {
	useCountingThresholdPersistenceCrypto(t)
	password := []byte("DEVNET ONLY threshold plaintext cache password")
	dir := t.TempDir()
	var firstEntry []byte
	for i := 0; i < 3*thresholdPlaintextCacheCapacity; i++ {
		path := filepath.Join(dir, fmt.Sprintf("blob-%d.enc", i))
		encoded, err := thresholdEncryptPersistenceBlob([]byte(fmt.Sprintf("plaintext %d", i)), password)
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicWriteThresholdFile(path, encoded); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadThresholdPlaintext(path, password); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstEntry = thresholdPlaintextCacheEntryForTest(encoded, password)
			if firstEntry == nil {
				t.Fatal("first plaintext was not cached")
			}
		}
	}
	if size := thresholdPlaintextCacheSize(); size > thresholdPlaintextCacheCapacity {
		t.Fatalf("cache holds %d entries; capacity is %d", size, thresholdPlaintextCacheCapacity)
	}
	for _, b := range firstEntry {
		if b != 0 {
			t.Fatal("evicted plaintext was not zeroized")
		}
	}
}

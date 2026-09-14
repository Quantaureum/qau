// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
)

// R99-POW-RECOMPUTE
//
// The proof-of-work handshake nonce was recomputed from scratch on every peer
// handshake while holding the process-wide powCacheMu. A slow search can
// serialize concurrent handshakes, cause connection deadlines to expire, and
// prevent the P2P mesh from forming.
//
// Two independent defects:
//
//  1. NO IN-PROCESS MEMOIZATION. The nonce is a pure function of (nodeID,
//     difficulty), both fixed for the process lifetime, but the on-disk file was
//     the only cache. Any failure to persist meant unconditional recomputation
//     forever — and because the search runs under powCacheMu, N concurrent
//     handshakes serialize behind N searches.
//
//  2. THE CACHE PATH IGNORED THE NODE'S DATA DIRECTORY. powCacheFilePath
//     honored only $QAU_DATA_DIR and otherwise fell back to
//     os.UserConfigDir() for a service. A hardened service may make that
//     location unreachable, while the node's writable data directory remains
//     available but unknown to this code path.
//
// The combination can prevent mesh formation. Fixing 1 makes the node correct
// even when the disk is unwritable; fixing 2 additionally avoids paying the
// cost once per restart.
//
// Note on the existing WARN: savePoWCache's failure WAS logged, every time. It
// is a textbook case of a correctly-reported silent fallback going unnoticed
// because it was buried in unrelated log volume.

// powMemo caches computed nonces for the process lifetime, keyed by
// "<nodeIDHex>:<difficulty>". Guarded by powCacheMu, the same mutex that
// serializes the search itself, so a lookup can never race a computation.
var powMemo = map[string][]byte{}

// powCacheDir is the node's data directory, installed by the owning Host so the
// on-disk cache lands somewhere the service can actually write. Empty means
// "not configured"; $QAU_DATA_DIR still takes precedence for compatibility with
// existing deployments and ops tooling.
var (
	powCacheDirMu sync.RWMutex
	powCacheDir   string
)

// powComputations counts completed PoW searches. Exists so tests can assert
// "computed exactly once" — the property that actually matters here — instead
// of timing the search.
var powComputations atomic.Uint64

// SetPoWCacheDir tells the PoW nonce cache which directory to persist into.
// Callers pass the node's data directory. Safe to call before or after Host
// creation; passing "" clears it.
func SetPoWCacheDir(dir string) {
	powCacheDirMu.Lock()
	powCacheDir = dir
	powCacheDirMu.Unlock()
}

func configuredPoWCacheDir() string {
	powCacheDirMu.RLock()
	defer powCacheDirMu.RUnlock()
	return powCacheDir
}

// powMemoKey builds the memo key. difficulty is part of the key because a
// harder nonce satisfies an easier requirement but not vice versa, mirroring
// loadPoWCache's own comparison.
func powMemoKey(nodeIDHex string, difficulty int) string {
	return nodeIDHex + ":" + strconv.Itoa(difficulty)
}

// lookupPoWMemo returns a memoized nonce. Caller must hold powCacheMu.
func lookupPoWMemoLocked(nodeIDHex string, difficulty int) []byte {
	return powMemo[powMemoKey(nodeIDHex, difficulty)]
}

// storePoWMemo records a computed nonce. Caller must hold powCacheMu.
func storePoWMemoLocked(nodeIDHex string, difficulty int, nonce []byte) {
	cp := make([]byte, len(nonce))
	copy(cp, nonce)
	powMemo[powMemoKey(nodeIDHex, difficulty)] = cp
}

// powComputeCount reports how many PoW searches have completed. Test hook.
func powComputeCount() uint64 { return powComputations.Load() }

// resetPoWCacheForTest clears the memo, the counter and the configured
// directory so tests start from a known state. Test hook.
func resetPoWCacheForTest() {
	powCacheMu.Lock()
	powMemo = map[string][]byte{}
	powCacheMu.Unlock()
	powComputations.Store(0)
	SetPoWCacheDir("")
}

// resolvePoWCachePath centralizes the precedence order for the on-disk cache
// location. Extracted so the ordering is testable and documented in one place.
//
// Precedence:
//  1. $QAU_DATA_DIR — explicit operator override; must keep winning so existing
//     deployments and ops scripts behave exactly as before.
//  2. the directory installed via SetPoWCacheDir — the node's own data
//     directory, which is writable by construction (it holds the chain DB).
//  3. os.UserConfigDir() — the pre-R99 fallback. Retained for non-service use
//     (CLI tools, local runs) but it is precisely what ProtectHome=true breaks.
//  4. the working directory.
func resolvePoWCachePath(envDataDir, configuredDir string, userConfigDir func() (string, error)) string {
	if envDataDir != "" {
		return filepath.Join(envDataDir, powCacheFile)
	}
	if configuredDir != "" {
		return filepath.Join(configuredDir, powCacheFile)
	}
	if dir, err := userConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "quantaureum", powCacheFile)
	}
	return powCacheFile
}

// powCacheFilePathR99 is the R99 replacement for the original
// powCacheFilePath body; kept as a thin wrapper so the precedence logic above
// stays pure and testable.
func powCacheFilePathR99() string {
	return resolvePoWCachePath(os.Getenv("QAU_DATA_DIR"), configuredPoWCacheDir(), os.UserConfigDir)
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/p2p/discover"
)

// R99-POW-RECOMPUTE regression tests.
//
// The P2P mesh can fail to form when every handshake recomputes the PoW nonce
// while generatePoWNonce holds the process-wide powCacheMu. A slow search
// serializes concurrent handshakes; connection deadlines then expire and
// retries can trip the per-IP limiter.
//
// Two independent defects combine:
//
//  1. No in-process memoization. The nonce depends only on (nodeID,
//     difficulty), both fixed for the life of the process, yet nothing kept the
//     result in memory. The on-disk cache was the ONLY cache, so any failure to
//     persist meant unconditional recomputation forever.
//
//  2. powCacheFilePath ignores the node's configured data directory. It honors
//     only $QAU_DATA_DIR and otherwise falls back to os.UserConfigDir(). A
//     hardened service can make that location unwritable even though the
//     node's data directory is available.
//
// The combination can turn a slow start-up into an inability to form a mesh.
// Fixing 1 makes the system correct even when the disk is unwritable; fixing 2
// avoids the cost once per process restart.

// TestR99_PoWNonceMemoizedWhenDiskCacheUnwritable is the core regression: with
// the on-disk cache pointed at an unwritable location, a second request must
// NOT recompute.
//
// Fails without the fix: powComputeCount == 2.
func TestR99_PoWNonceMemoizedWhenDiskCacheUnwritable(t *testing.T) {
	resetPoWCacheForTest()
	t.Cleanup(resetPoWCacheForTest)

	// Point the disk cache at a path that cannot be created: a *file* used as
	// a parent directory. This reproduces "mkdir ...: read-only file system"
	// without needing a read-only mount.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	t.Setenv("QAU_DATA_DIR", filepath.Join(blocker, "nested"))

	nodeID := make([]byte, 32)
	for i := range nodeID {
		nodeID[i] = byte(i + 1)
	}

	before := powComputeCount()
	first, err := generatePoWNonce(nodeID, false)
	if err != nil {
		t.Fatalf("first generatePoWNonce: %v", err)
	}
	afterFirst := powComputeCount()
	if afterFirst != before+1 {
		t.Fatalf("first call should compute exactly once, got %d computations", afterFirst-before)
	}

	second, err := generatePoWNonce(nodeID, false)
	if err != nil {
		t.Fatalf("second generatePoWNonce: %v", err)
	}
	if got := powComputeCount(); got != afterFirst {
		t.Errorf("second call recomputed the nonce (%d computations, want %d) even though the "+
			"nodeID and difficulty are unchanged.\n"+
			"Each handshake pays the full search cost while holding powCacheMu, serializing "+
			"every peer connection and preventing the mesh from forming (R99-POW-RECOMPUTE).",
			got-before, afterFirst-before)
	}
	if hex.EncodeToString(first) != hex.EncodeToString(second) {
		t.Errorf("memoized nonce differs from the computed one: %x vs %x", first, second)
	}
}

// TestR99_PoWNonceMemoIsPerNodeID guards against over-caching: a different
// node identity must get its own nonce, never the previous one.
func TestR99_PoWNonceMemoIsPerNodeID(t *testing.T) {
	resetPoWCacheForTest()
	t.Cleanup(resetPoWCacheForTest)
	t.Setenv("QAU_DATA_DIR", t.TempDir())

	idA := make([]byte, 32)
	idB := make([]byte, 32)
	for i := range idA {
		idA[i] = byte(i + 1)
		idB[i] = byte(255 - i)
	}

	nonceA, err := generatePoWNonce(idA, false)
	if err != nil {
		t.Fatalf("generatePoWNonce(idA): %v", err)
	}
	nonceB, err := generatePoWNonce(idB, false)
	if err != nil {
		t.Fatalf("generatePoWNonce(idB): %v", err)
	}

	if hex.EncodeToString(nonceA) == hex.EncodeToString(nonceB) {
		t.Error("two different node IDs received the same nonce — the memo must be keyed by " +
			"nodeID, otherwise a node would advertise a nonce that fails the peer's verification")
	}

	// Each must still satisfy the PoW target for its OWN id — that is what the
	// remote peer verifies. Recomputed here rather than calling
	// discover.VerifyProofOfWork, whose signature takes an enode.ID and a
	// uint64 nonce; this keeps the assertion on the exact bytes generatePoWNonce
	// returns.
	if !r99SatisfiesPoW(idA, nonceA, discover.MinProofOfWorkDifficulty) {
		t.Error("nonce for idA does not satisfy the PoW target for idA")
	}
	if !r99SatisfiesPoW(idB, nonceB, discover.MinProofOfWorkDifficulty) {
		t.Error("nonce for idB does not satisfy the PoW target for idB")
	}
}

// TestR99_ConcurrentHandshakesComputeOnce models six peers handshaking at once
// on a freshly started node. Exactly one computation may
// happen; the other five must reuse it.
//
// Fails without the fix: 6 computations, serialized — 195 s of lock hold on the
// measured hardware, which is why handshakes hit their I/O deadline.
func TestR99_ConcurrentHandshakesComputeOnce(t *testing.T) {
	resetPoWCacheForTest()
	t.Cleanup(resetPoWCacheForTest)
	t.Setenv("QAU_DATA_DIR", t.TempDir())

	nodeID := make([]byte, 32)
	for i := range nodeID {
		nodeID[i] = byte(i * 3)
	}

	const peers = 6
	before := powComputeCount()
	var wg sync.WaitGroup
	errs := make([]error, peers)
	nonces := make([][]byte, peers)
	for i := range peers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonces[idx], errs[idx] = generatePoWNonce(nodeID, false)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := powComputeCount() - before; got != 1 {
		t.Errorf("%d concurrent handshakes triggered %d PoW computations, want exactly 1 — "+
			"each one holds powCacheMu for the full search, so N computations serialize into "+
			"the mesh cannot form (R99-POW-RECOMPUTE)", peers, got)
	}
	for i := 1; i < peers; i++ {
		if hex.EncodeToString(nonces[i]) != hex.EncodeToString(nonces[0]) {
			t.Errorf("goroutine %d got a different nonce than goroutine 0", i)
		}
	}
}

// TestR99_PoWCachePathPrefersConfiguredDataDir pins defect 2: the cache must be
// placeable in the node's own data directory instead of an OS user directory
// that ProtectHome makes unreachable.
func TestR99_PoWCachePathPrefersConfiguredDataDir(t *testing.T) {
	dir := t.TempDir()
	SetPoWCacheDir(dir)
	t.Cleanup(func() { SetPoWCacheDir("") })

	got := powCacheFilePath()
	want := filepath.Join(dir, powCacheFile)
	if got != want {
		t.Errorf("powCacheFilePath() = %q, want %q — the node knows its data directory and "+
			"must use it; falling back to os.UserConfigDir() lands in /root/.config, which "+
			"systemd ProtectHome=true renders unwritable (R99-POW-RECOMPUTE defect 2)", got, want)
	}

	// $QAU_DATA_DIR must keep working and must win, so existing deployments and
	// the ops tooling that sets it are unaffected.
	envDir := t.TempDir()
	t.Setenv("QAU_DATA_DIR", envDir)
	if got := powCacheFilePath(); got != filepath.Join(envDir, powCacheFile) {
		t.Errorf("QAU_DATA_DIR must take precedence; got %q", got)
	}
}

// r99SatisfiesPoW mirrors the target check inside generatePoWNonce /
// loadPoWCache: SHA3-256(nodeID || nonce) must be below 2^(256-difficulty).
func r99SatisfiesPoW(nodeID, nonce []byte, difficulty int) bool {
	target := new(big.Int).Lsh(big.NewInt(1), 256-uint(difficulty))
	h := sha3.New256()
	h.Write(nodeID)
	h.Write(nonce)
	return new(big.Int).SetBytes(h.Sum(nil)).Cmp(target) < 0
}

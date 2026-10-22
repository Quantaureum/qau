// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	bolt "go.etcd.io/bbolt"
)

func testNonce(now time.Time, ttl time.Duration) string {
	return fmt.Sprintf("%d:%s", now.Add(ttl).Unix(), strings.Repeat("ab", 24))
}

func TestParseAuthNonceDeadline(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		nonce   string
		wantErr bool
	}{
		{"valid", testNonce(now, 5*time.Minute), false},
		{"valid at past skew boundary", testNonce(now, -10*time.Second), false},
		{"expired", testNonce(now, -2*time.Minute), true},
		{"too far in the future", testNonce(now, 11*time.Minute), true},
		{"empty", "", true},
		{"legacy hex without deadline", strings.Repeat("ab", 24), true},
		{"missing random", fmt.Sprintf("%d:", now.Unix()+60), true},
		{"short random", fmt.Sprintf("%d:abcd", now.Unix()+60), true},
		{"non numeric deadline", "12ab:" + strings.Repeat("ab", 24), true},
		{"zero deadline", "0:" + strings.Repeat("ab", 24), true},
		{"oversized", strings.Repeat("9", 200) + ":" + strings.Repeat("ab", 24), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAuthNonceDeadline(tt.nonce, now)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for nonce %q", tt.nonce)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for nonce %q: %v", tt.nonce, err)
			}
		})
	}
}

func TestParseAuthDeadline(t *testing.T) {
	now := time.Now()
	if _, err := ParseAuthDeadline(fmt.Sprintf("%d", now.Add(2*time.Minute).Unix()), now); err != nil {
		t.Fatalf("valid deadline rejected: %v", err)
	}
	if _, err := ParseAuthDeadline(fmt.Sprintf("%d", now.Add(-time.Minute).Unix()), now); err == nil {
		t.Fatal("expired deadline accepted")
	}
	if _, err := ParseAuthDeadline("", now); err == nil {
		t.Fatal("empty deadline accepted")
	}
	if _, err := ParseAuthDeadline("deadline", now); err == nil {
		t.Fatal("non-numeric deadline accepted")
	}
}

func TestAuthReplayGuardInMemory(t *testing.T) {
	g := newAuthReplayGuard("defi")
	addr := types.Address{1}
	deadline := time.Now().Add(5 * time.Minute)
	nonce := testNonce(time.Now(), 5*time.Minute)

	if err := g.reserve(addr, nonce, deadline); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if err := g.reserve(addr, nonce, deadline); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("second reserve: err = %v, want ErrAuthNonceReused", err)
	}

	// R2-02: a request whose deadline passed less than the accepted skew ago
	// is still valid, so its nonce must stay reserved rather than being
	// reclaimed at the raw deadline.
	graceNonce := testNonce(time.Now(), -10*time.Second)
	graceDeadline := time.Now().Add(-10 * time.Second)
	if err := g.reserve(addr, graceNonce, graceDeadline); err != nil {
		t.Fatalf("reserve inside grace window: %v", err)
	}
	if err := g.reserve(addr, graceNonce, graceDeadline); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("grace-window replay: err = %v, want ErrAuthNonceReused", err)
	}

	// Once deadline+skew has fully passed the entry is reclaimed.
	expired := testNonce(time.Now(), -time.Minute)
	pastDeadline := time.Now().Add(-time.Minute)
	if err := g.reserve(addr, expired, pastDeadline); err != nil {
		t.Fatalf("reserve expired: %v", err)
	}
	if err := g.reserve(addr, expired, deadline); err != nil {
		t.Fatalf("expired reservation was not reclaimed: %v", err)
	}
}

func TestAuthReplayStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rpc", "auth_replay.db")
	addr := types.Address{2}
	nonce := testNonce(time.Now(), 5*time.Minute)
	deadline := time.Now().Add(5 * time.Minute)

	store, err := OpenAuthReplayStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Reserve("defi", addr, nonce, deadline); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenAuthReplayStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	if err := reopened.Reserve("defi", addr, nonce, deadline); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("replay after reopen: err = %v, want ErrAuthNonceReused", err)
	}
	// Namespaces are isolated: the same nonce may be used by another API.
	if err := reopened.Reserve("staking", addr, nonce, deadline); err != nil {
		t.Fatalf("same nonce in another namespace: %v", err)
	}
}

func TestAuthReplayStorePrunesExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_replay.db")
	store, err := OpenAuthReplayStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	addr := types.Address{3}
	nonce := testNonce(time.Now(), -time.Minute)
	if err := store.Reserve("economics", addr, nonce, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("reserve expired: %v", err)
	}
	if err := store.Prune(time.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := store.Reserve("economics", addr, nonce, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("reserve after prune: %v", err)
	}
}

// signDeFiRequest produces the exact message verifyDeFiSignature expects.
func signDeFiRequest(t *testing.T, kp *crypto.KeyPair, chainID uint64, method, nonce, params string) (string, string) {
	t.Helper()
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s", method, chainID, kp.Public.Address().ToHexAddress(), nonce, params))
	sig, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return "0x" + hex.EncodeToString(sig), "0x" + hex.EncodeToString(kp.Public.Bytes())
}

func TestDeFiSignatureReplayRejected(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false)
	api.SetChainID(1668)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	nonce := testNonce(time.Now(), 5*time.Minute)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("replay: err = %v, want ErrAuthNonceReused", err)
	}
}

func TestDeFiSignatureFailedVerificationDoesNotConsumeNonce(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false)
	api.SetChainID(1668)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	nonce := testNonce(time.Now(), 5*time.Minute)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "999", sig, pub); err == nil {
		t.Fatal("tampered params accepted")
	}
	// The failed attempt must not consume the nonce.
	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); err != nil {
		t.Fatalf("retry after failed verification rejected: %v", err)
	}
}

func TestDeFiSignatureExpiredNonceRejected(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false)
	api.SetChainID(1668)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := testNonce(time.Now(), -time.Minute)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	err = api.verifyDeFiSignature("qau_supply", kp.Public.Address(), nonce, "100", sig, pub)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired nonce: err = %v, want expiry error", err)
	}
}

func TestGovernanceSignatureBindsDeadline(t *testing.T) {
	api := NewGovernanceAPI(nil, nil)
	api.SetChainID(1668)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	deadline := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())
	const nonce = "42"
	const params = "1|voter|0|1000"

	message := []byte(fmt.Sprintf("QAU-qau_castVote|%d|%s|%s|%s|%s", uint64(1668), addr.ToHexAddress(), nonce, deadline, params))
	sig, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigHex := "0x" + hex.EncodeToString(sig)
	pubHex := "0x" + hex.EncodeToString(kp.Public.Bytes())

	if err := api.verifyGovernanceSignature("qau_castVote", addr, nonce, deadline, params, sigHex, pubHex); err != nil {
		t.Fatalf("valid governance signature rejected: %v", err)
	}
	if err := api.verifyGovernanceSignature("qau_castVote", addr, nonce, deadline, params, sigHex, pubHex); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("governance replay: err = %v, want ErrAuthNonceReused", err)
	}

	// A different deadline no longer matches the signed message.
	other := NewGovernanceAPI(nil, nil)
	other.SetChainID(1668)
	deadline2 := fmt.Sprintf("%d", time.Now().Add(6*time.Minute).Unix())
	if err := other.verifyGovernanceSignature("qau_castVote", addr, nonce, deadline2, params, sigHex, pubHex); err == nil {
		t.Fatal("tampered deadline accepted")
	}
}

// TestDeFiSignatureRejectsWrongChainID pins the cross-chain domain separation
// that SetChainID enables: a signature produced for one chain must not verify
// on an API bound to a different chain ID (the node wires n.chainID via
// SetChainID in initRPC; before that wiring the field stayed 0 and the domain
// separator was inert).
func TestDeFiSignatureRejectsWrongChainID(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	nonce := testNonce(time.Now(), 5*time.Minute)

	// Signature produced against the mainnet chain ID.
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	mainnetAPI := NewDeFiAPI(nil, nil)
	mainnetAPI.SetEnforceAdminAuth(false)
	mainnetAPI.SetChainID(1668)
	if err := mainnetAPI.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); err != nil {
		t.Fatalf("same-chain signature rejected: %v", err)
	}

	// The same request must fail on a differently-bound API. A fresh nonce is
	// used so the rejection comes from the domain mismatch, not replay.
	nonce2 := testNonce(time.Now().Add(time.Second), 5*time.Minute)
	sig2, _ := signDeFiRequest(t, kp, 1668, "qau_supply", nonce2, "100")
	testnetAPI := NewDeFiAPI(nil, nil)
	testnetAPI.SetEnforceAdminAuth(false)
	testnetAPI.SetChainID(1669)
	if err := testnetAPI.verifyDeFiSignature("qau_supply", addr, nonce2, "100", sig2, pub); err == nil {
		t.Fatal("cross-chain signature accepted: chainID domain separator is not enforced")
	}

	// The same nonce/signature pair must also fail against an unwired API
	// (chainID zero default), proving the binding is load-bearing.
	nonce3 := testNonce(time.Now().Add(2*time.Second), 5*time.Minute)
	sig3, _ := signDeFiRequest(t, kp, 1668, "qau_supply", nonce3, "100")
	unwiredAPI := NewDeFiAPI(nil, nil)
	unwiredAPI.SetEnforceAdminAuth(false)
	if err := unwiredAPI.verifyDeFiSignature("qau_supply", addr, nonce3, "100", sig3, pub); err == nil {
		t.Fatal("signature bound to chainID 1668 accepted by unwired API (chainID=0)")
	}
}

// TestAuthReplayStoreGraceWindowRetained pins R2-02 at the storage layer: an
// entry whose raw deadline has passed but which is still inside the accepted
// clock-skew window must not be reclaimed.
func TestAuthReplayStoreGraceWindowRetained(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	addr := types.Address{5}
	nonce := testNonce(time.Now(), -10*time.Second)
	graceDeadline := time.Now().Add(-10 * time.Second)

	if err := store.Reserve("defi", addr, nonce, graceDeadline); err != nil {
		t.Fatalf("reserve inside grace window: %v", err)
	}
	if err := store.Reserve("defi", addr, nonce, graceDeadline); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("grace-window replay: err = %v, want ErrAuthNonceReused", err)
	}
}

// TestAuthReplayStorePeriodicPrune verifies that expired entries are purged by
// the background loop, not only at startup (R2-06).
func TestAuthReplayStorePeriodicPrune(t *testing.T) {
	store, err := openAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	addr := types.Address{6}
	nonce := testNonce(time.Now(), -time.Minute)
	if err := store.Reserve("economics", addr, nonce, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("reserve expired: %v", err)
	}

	key := expireKey(replayKey("economics", addr, nonce))
	limit := time.Now().Add(3 * time.Second)
	for {
		var present bool
		if err := store.db.View(func(tx *bolt.Tx) error {
			present = tx.Bucket(authReplayBucket).Get(key) != nil
			return nil
		}); err != nil {
			t.Fatalf("read store: %v", err)
		}
		if !present {
			return
		}
		if time.Now().After(limit) {
			t.Fatal("expired replay entry was not pruned by the background loop")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAuthReplayStorePruneBatchBounded pins R3-07: a single write transaction
// must delete at most the requested limit, and permanent entries must survive
// every batch.
func TestAuthReplayStorePruneBatchBounded(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now()
	if err := store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		for i := 0; i < 7; i++ {
			key := expireKey(fmt.Sprintf("economics|addr|nonce-%d", i))
			if err := b.Put(key, encodeExpiry(now.Add(-time.Minute).Unix())); err != nil {
				return err
			}
		}
		return b.Put(permanentKey("economics|addr|legacy"), []byte{1})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	for i, want := range []int{3, 3, 1, 0} {
		removed, err := store.pruneBatch(now.Unix(), 3)
		if err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
		if removed != want {
			t.Fatalf("batch %d removed %d entries, want %d", i, removed, want)
		}
	}

	if err := store.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		if b.Get(permanentKey("economics|addr|legacy")) == nil {
			t.Error("permanent entry was pruned")
		}
		return nil
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
}

// TestAuthReplayStorePruneDrainsInBatches verifies that Prune keeps running
// batches until the expired backlog is gone, not just the first chunk.
func TestAuthReplayStorePruneDrainsInBatches(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now()
	total := authReplayPruneBatchSize*2 + 17
	if err := store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		for i := 0; i < total; i++ {
			key := expireKey(fmt.Sprintf("defi|addr|nonce-%d", i))
			if err := b.Put(key, encodeExpiry(now.Add(-time.Minute).Unix())); err != nil {
				return err
			}
		}
		return b.Put(permanentKey("defi|addr|legacy"), []byte{1})
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if err := store.Prune(now); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if err := store.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		remaining := 0
		if err := b.ForEach(func(k, _ []byte) error {
			if string(k) != string(permanentKey("defi|addr|legacy")) {
				remaining++
			}
			return nil
		}); err != nil {
			return err
		}
		if remaining != 0 {
			t.Errorf("prune left %d expired entries", remaining)
		}
		if b.Get(permanentKey("defi|addr|legacy")) == nil {
			t.Error("permanent entry was pruned")
		}
		return nil
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
}

// TestAuthReplayGuardNilFailsClosed pins R2-11: a nil guard must reject the
// request rather than silently accepting an unreserved nonce.
func TestAuthReplayGuardNilFailsClosed(t *testing.T) {
	var g *authReplayGuard
	nonce := testNonce(time.Now(), time.Minute)
	err := g.reserve(types.Address{7}, nonce, time.Now().Add(time.Minute))
	if !errors.Is(err, errAuthReplayGuardUnavailable) {
		t.Fatalf("nil guard reserve: err = %v, want errAuthReplayGuardUnavailable", err)
	}
}

// TestDeFiFailedVerificationDoesNotWriteReplayStore pins R2-03: a request that
// fails signature verification must not create a persistent replay record.
func TestDeFiFailedVerificationDoesNotWriteReplayStore(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false)
	api.SetChainID(1668)
	api.replay.setStore(store)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	nonce := testNonce(time.Now(), 5*time.Minute)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "999", sig, pub); err == nil {
		t.Fatal("tampered params accepted")
	}

	var entries int
	if err := store.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(authReplayBucket).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			entries++
		}
		return nil
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
	if entries != 0 {
		t.Fatalf("failed verification wrote %d replay entries, want 0", entries)
	}

	if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

// TestDeFiNilReplayGuardFailsClosed pins R2-11 at the API boundary: a valid
// signature must still be rejected when replay protection is unavailable.
func TestDeFiNilReplayGuardFailsClosed(t *testing.T) {
	api := &DeFiAPI{}
	api.SetChainID(1668)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nonce := testNonce(time.Now(), 5*time.Minute)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")

	err = api.verifyDeFiSignature("qau_supply", kp.Public.Address(), nonce, "100", sig, pub)
	if !errors.Is(err, errAuthReplayGuardUnavailable) {
		t.Fatalf("nil replay guard: err = %v, want errAuthReplayGuardUnavailable", err)
	}
}

// signEconomicsRequest produces the exact message verifyEconomicsSignature
// expects (R2-04: QAU-{method}|chainID|address|nonce|params).
func signEconomicsRequest(t *testing.T, kp *crypto.KeyPair, chainID uint64, method, nonce, params string) (string, string) {
	t.Helper()
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s", method, chainID, kp.Public.Address().ToHexAddress(), nonce, params))
	sig, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return "0x" + hex.EncodeToString(sig), "0x" + hex.EncodeToString(kp.Public.Bytes())
}

// TestEconomicsSignatureBindsChainID pins R2-04: the economics domain must
// include the chain ID so a signature from one chain cannot be replayed on
// another.
func TestEconomicsSignatureBindsChainID(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	const method = "qau_buyLiquidStaking"
	nonce := testNonce(time.Now(), 5*time.Minute)
	sig, pub := signEconomicsRequest(t, kp, 1668, method, nonce, "100")

	mainnet := NewEconomicsAPI(nil, nil, nil, nil, nil, nil, nil, nil, nil)
	mainnet.SetChainID(1668)
	if err := mainnet.verifyEconomicsSignature(method, addr, nonce, "100", sig, pub); err != nil {
		t.Fatalf("same-chain signature rejected: %v", err)
	}
	if err := mainnet.verifyEconomicsSignature(method, addr, nonce, "100", sig, pub); !errors.Is(err, ErrAuthNonceReused) {
		t.Fatalf("economics replay: err = %v, want ErrAuthNonceReused", err)
	}

	nonce2 := testNonce(time.Now().Add(time.Second), 5*time.Minute)
	sig2, _ := signEconomicsRequest(t, kp, 1668, method, nonce2, "100")
	testnet := NewEconomicsAPI(nil, nil, nil, nil, nil, nil, nil, nil, nil)
	testnet.SetChainID(1669)
	if err := testnet.verifyEconomicsSignature(method, addr, nonce2, "100", sig2, pub); err == nil {
		t.Fatal("cross-chain economics signature accepted: chainID is not bound")
	}
}

// TestAuthReplayGuardConcurrentReserveSingleWinner pins the atomicity of the
// reserve gate: verify-after-sign-then-reserve makes Reserve the sole TOCTOU
// guard, so N concurrent submissions of the same nonce must produce exactly
// one winner. This holds for both the in-memory guard and the persistent
// store path.
func TestAuthReplayGuardConcurrentReserveSingleWinner(t *testing.T) {
	const goroutines = 32
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()
	nonce := testNonce(time.Now(), 5*time.Minute)
	_, err = ParseAuthNonceDeadline(nonce, time.Now())
	if err != nil {
		t.Fatalf("ParseAuthNonceDeadline: %v", err)
	}

	runRace := func(api *DeFiAPI, nonce, sig, pub string) int {
		var wg sync.WaitGroup
		var wins atomic.Int32
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := api.verifyDeFiSignature("qau_supply", addr, nonce, "100", sig, pub); err == nil {
					wins.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		return int(wins.Load())
	}

	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false)
	api.SetChainID(1668)
	sig, pub := signDeFiRequest(t, kp, 1668, "qau_supply", nonce, "100")
	if got := runRace(api, nonce, sig, pub); got != 1 {
		t.Fatalf("in-memory guard: %d winners for the same nonce, want exactly 1", got)
	}

	// Same race against the persistent bbolt store.
	dir := t.TempDir()
	store, err := OpenAuthReplayStore(filepath.Join(dir, "replay.db"))
	if err != nil {
		t.Fatalf("OpenAuthReplayStore: %v", err)
	}
	defer store.Close()
	persisted := NewDeFiAPI(nil, nil)
	persisted.SetEnforceAdminAuth(false)
	persisted.SetChainID(1668)
	persisted.SetAuthReplayStore(store)

	nonce2 := testNonce(time.Now().Add(2*time.Second), 5*time.Minute)
	sig2, pub2 := signDeFiRequest(t, kp, 1668, "qau_supply", nonce2, "100")
	if got := runRace(persisted, nonce2, sig2, pub2); got != 1 {
		t.Fatalf("persistent store: %d winners for the same nonce, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// R4-05: the replay store must degrade to a fail-closed error, not a panic,
// when a signed RPC request is still in flight while the node shuts the store
// down (Node.Stop releases it after both RPC transports stop serving).
// ---------------------------------------------------------------------------

func TestAuthReplayStore_AfterCloseReserveAndPruneFailClosed(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	addr := types.Address{9}
	nonce := testNonce(time.Now(), 5*time.Minute)
	if err := store.Reserve("staking", addr, nonce, time.Now().Add(5*time.Minute)); !errors.Is(err, ErrAuthReplayStoreClosed) {
		t.Fatalf("Reserve after Close: err = %v, want ErrAuthReplayStoreClosed", err)
	}
	if err := store.Prune(time.Now()); !errors.Is(err, ErrAuthReplayStoreClosed) {
		t.Fatalf("Prune after Close: err = %v, want ErrAuthReplayStoreClosed", err)
	}
	// Close stays idempotent after the handle was released.
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestAuthReplayStore_ConcurrentReserveAndCloseIsSafe(t *testing.T) {
	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := types.Address{byte(i + 1)}
			for j := 0; j < 20; j++ {
				nonce := testNonce(time.Now(), time.Duration(5+j)*time.Minute)
				err := store.Reserve("defi", addr, nonce, time.Now().Add(5*time.Minute))
				if err != nil && !errors.Is(err, ErrAuthReplayStoreClosed) && !errors.Is(err, ErrAuthNonceReused) {
					t.Errorf("Reserve: unexpected error %v", err)
					return
				}
			}
		}(i)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// R4-06: the nonce is client-controlled and becomes part of the replay record
// key. The governance namespace carries a free-form nonce next to an explicit
// deadline, so the bound has to live at the replay boundary itself.
// ---------------------------------------------------------------------------

func TestAuthReplayGuard_RejectsOversizedNonce(t *testing.T) {
	deadline := time.Now().Add(5 * time.Minute)
	longNonce := strings.Repeat("f", authNonceMaxLen+1)

	guard := newAuthReplayGuard("governance")
	if err := guard.reserve(types.Address{7}, longNonce, deadline); err == nil ||
		!strings.Contains(err.Error(), "nonce is too long") {
		t.Fatalf("oversized nonce accepted by in-memory guard: %v", err)
	}
	if err := guard.reserve(types.Address{7}, "", deadline); err == nil {
		t.Fatal("empty nonce accepted by in-memory guard")
	}

	store, err := OpenAuthReplayStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.Reserve("governance", types.Address{7}, longNonce, deadline); err == nil ||
		!strings.Contains(err.Error(), "nonce is too long") {
		t.Fatalf("oversized nonce accepted by persistent store: %v", err)
	}
	// A nonce that fits the per-field cap but pushes the composite key past the
	// record bound is rejected too.
	boundary := strings.Repeat("f", authNonceMaxLen)
	if err := store.Reserve(strings.Repeat("n", 200), types.Address{7}, boundary, deadline); err == nil ||
		!strings.Contains(err.Error(), "replay key too long") {
		t.Fatalf("oversized composite key accepted: %v", err)
	}
}

func TestGovernanceOversizedNonceRejectedAfterVerify(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dir := t.TempDir()
	store, err := OpenAuthReplayStore(filepath.Join(dir, "replay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	api := NewGovernanceAPI(nil, nil)
	api.SetChainID(1668)
	api.SetAuthReplayStore(store)

	nonce := strings.Repeat("e", authNonceMaxLen+1)
	deadline := fmt.Sprintf("%d", time.Now().Add(5*time.Minute).Unix())
	params := "1|0x0000000000000000000000000000000000000001|1|100"
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s|%s", "qau_castVote", uint64(1668),
		kp.Public.Address().ToHexAddress(), nonce, deadline, params))
	sig, err := kp.Private.Sign(message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	err = api.verifyGovernanceSignature("qau_castVote", kp.Public.Address(), nonce, deadline, params,
		"0x"+hex.EncodeToString(sig), "0x"+hex.EncodeToString(kp.Public.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "nonce is too long") {
		t.Fatalf("oversized governance nonce: err = %v, want length rejection", err)
	}

	// The reservation must not have been written for the rejected request.
	reserved := api.replay.reserve(kp.Public.Address(), strings.Repeat("e", 40)+":"+strings.Repeat("f", 20),
		time.Now().Add(5*time.Minute))
	if reserved != nil {
		t.Fatalf("control reservation failed: %v", reserved)
	}
}

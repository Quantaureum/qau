// Quantaureum Node source, version 1.0.0.
// Package rpc provides the JSON-RPC server and API handlers.
package rpc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	bolt "go.etcd.io/bbolt"
)

const (
	// authNonceMaxLen bounds the replay-cache key size and rejects oversized
	// client input before it reaches storage.
	authNonceMaxLen = 160

	// authDeadlineMaxValidity is the furthest a signed request deadline may
	// sit in the future. Clients normally use 5 minutes; the extra margin
	// tolerates clock skew between the signer and the node.
	authDeadlineMaxValidity = 10 * time.Minute

	// authDeadlinePastSkew tolerates a small amount of clock skew for
	// requests that were signed immediately before arriving at the node.
	authDeadlinePastSkew = 30 * time.Second

	// authNonceRandomMinLen is the minimum length of the random suffix. It
	// keeps client-generated nonces from being trivially enumerable.
	authNonceRandomMinLen = 16

	// authReplayPruneInterval controls how often expired replay entries are
	// purged in the background. Without it the database only shrank on restart
	// (R2-06), so long-running nodes accumulated one record per signed request.
	authReplayPruneInterval = time.Hour

	// authReplayPruneBatchSize bounds the number of expired entries removed in
	// a single write transaction. A full-table prune in one Update held the
	// bbolt write lock for the whole scan and stalled Reserve on large tables
	// (R3-07); each batch now releases the lock between chunks.
	authReplayPruneBatchSize = 256

	// authReplayMaxKeyLen caps the composite replay key (namespace + address +
	// nonce). The nonce is what a client controls, so the cap is what bounds a
	// caller who holds one valid key and submits authenticated requests with
	// oversized nonces (R4-06).
	authReplayMaxKeyLen = 320
)

var (
	// ErrAuthNonceReused is returned when a nonce was already consumed.
	ErrAuthNonceReused = errors.New("nonce already used (replay detected)")

	// ErrAuthReplayStoreClosed is returned by a store that was closed while the
	// node was shutting down. Reserve fails closed with this error instead of
	// dereferencing the released bbolt handle (R4-05).
	ErrAuthReplayStoreClosed = errors.New("auth replay store is closed")

	// errAuthReplayGuardUnavailable is returned by a nil guard instead of
	// silently disabling replay protection (R2-11).
	errAuthReplayGuardUnavailable = errors.New("auth replay guard is not initialized")

	authReplayBucket = []byte("auth-replay")
	expirePrefix     = []byte("e:")
	permanentPrefix  = []byte("p:")
)

// ParseAuthNonceDeadline extracts the signed deadline from a nonce of the form
// "<unix-seconds>:<random>". The deadline is part of the nonce, and therefore
// part of every signed payload that binds the nonce, which makes expiry
// cryptographically enforced rather than dependent on in-memory state.
//
// Legacy nonces without a deadline are rejected: accepting them would preserve
// the unbounded replay window that this guard exists to close.
func ParseAuthNonceDeadline(nonce string, now time.Time) (time.Time, error) {
	if nonce == "" {
		return time.Time{}, fmt.Errorf("nonce is required for replay protection")
	}
	if len(nonce) > authNonceMaxLen {
		return time.Time{}, fmt.Errorf("nonce is too long (max %d bytes)", authNonceMaxLen)
	}
	sep := strings.IndexByte(nonce, ':')
	if sep <= 0 || sep == len(nonce)-1 {
		return time.Time{}, fmt.Errorf("invalid nonce format: expected <unixDeadline>:<random>")
	}
	deadlineStr := nonce[:sep]
	random := nonce[sep+1:]
	if len(deadlineStr) == 0 || len(deadlineStr) > 10 {
		return time.Time{}, fmt.Errorf("invalid nonce deadline")
	}
	for i := 0; i < len(deadlineStr); i++ {
		if deadlineStr[i] < '0' || deadlineStr[i] > '9' {
			return time.Time{}, fmt.Errorf("invalid nonce deadline")
		}
	}
	if len(random) < authNonceRandomMinLen {
		return time.Time{}, fmt.Errorf("nonce random suffix is too short (min %d bytes)", authNonceRandomMinLen)
	}
	deadlineUnix, err := strconv.ParseInt(deadlineStr, 10, 64)
	if err != nil || deadlineUnix <= 0 {
		return time.Time{}, fmt.Errorf("invalid nonce deadline")
	}
	deadline := time.Unix(deadlineUnix, 0)
	if now.After(deadline.Add(authDeadlinePastSkew)) {
		return time.Time{}, fmt.Errorf("signature deadline expired at %s", deadline.UTC().Format(time.RFC3339))
	}
	if deadline.After(now.Add(authDeadlineMaxValidity)) {
		return time.Time{}, fmt.Errorf("signature deadline is too far in the future")
	}
	return deadline, nil
}

// ParseAuthDeadline parses an explicit deadline field (used by JSON-shaped
// governance requests) and applies the same freshness rules as nonce-embedded
// deadlines.
func ParseAuthDeadline(raw string, now time.Time) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("deadline is required for replay protection")
	}
	if len(raw) > 10 {
		return time.Time{}, fmt.Errorf("invalid deadline")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return time.Time{}, fmt.Errorf("invalid deadline")
		}
	}
	deadlineUnix, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || deadlineUnix <= 0 {
		return time.Time{}, fmt.Errorf("invalid deadline")
	}
	deadline := time.Unix(deadlineUnix, 0)
	if now.After(deadline.Add(authDeadlinePastSkew)) {
		return time.Time{}, fmt.Errorf("signature deadline expired at %s", deadline.UTC().Format(time.RFC3339))
	}
	if deadline.After(now.Add(authDeadlineMaxValidity)) {
		return time.Time{}, fmt.Errorf("signature deadline is too far in the future")
	}
	return deadline, nil
}

// AuthReplayStore is a process-external replay cache. Entries are keyed by
// namespace + address + nonce and carry the signed expiry, so a node restart
// (or rolling restart) cannot reopen a replay window for a signature that was
// already accepted.
type AuthReplayStore struct {
	// opMu serializes database access against Close. bbolt panics on any use of
	// a closed handle, so Reserve/Prune must hold this lock while touching db and
	// Close must take it exclusively before releasing the handle (R4-05).
	opMu   sync.RWMutex
	closed bool

	db *bolt.DB

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// OpenAuthReplayStore opens (or creates) the replay database at path.
func OpenAuthReplayStore(path string) (*AuthReplayStore, error) {
	return openAuthReplayStore(path, authReplayPruneInterval)
}

// openAuthReplayStore is the internal constructor; pruneInterval is a
// parameter so tests can exercise the background loop without mutating a
// package-global variable.
func openAuthReplayStore(path string, pruneInterval time.Duration) (*AuthReplayStore, error) {
	if path == "" {
		return nil, fmt.Errorf("auth replay store path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create auth replay dir: %w", err)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open auth replay store: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(authReplayBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init auth replay store: %w", err)
	}
	s := &AuthReplayStore{
		db:   db,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if err := s.Prune(time.Now()); err != nil {
		_ = db.Close()
		return nil, err
	}
	go s.pruneLoop(pruneInterval)
	return s, nil
}

// Close stops the background pruner and releases the database handle.
// Idempotent: the bbolt handle is closed inside the same once-guard as the
// pruner shutdown, so a second Close returns nil instead of bbolt's
// ErrDatabaseNotOpen.
func (s *AuthReplayStore) Close() error {
	if s == nil || s.stop == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.stop)
		// Wait for the pruner to leave its current transaction before taking
		// opMu; acquiring it first would deadlock against a prune in flight.
		<-s.done
		s.opMu.Lock()
		defer s.opMu.Unlock()
		s.closed = true
		if s.db != nil {
			closeErr = s.db.Close()
		}
	})
	return closeErr
}

// beginOp acquires the database for one operation. ok is false once the store
// is closed, so callers fail closed instead of touching a released handle.
func (s *AuthReplayStore) beginOp() (*bolt.DB, bool) {
	s.opMu.RLock()
	if s.closed || s.db == nil {
		s.opMu.RUnlock()
		return nil, false
	}
	return s.db, true
}

func (s *AuthReplayStore) pruneLoop(interval time.Duration) {
	defer close(s.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			select {
			case <-s.stop:
				return
			default:
			}
			if err := s.Prune(now); err != nil {
				logging.Warn("auth replay periodic prune failed", map[string]any{
					"module": "rpc",
					"error":  err.Error(),
				})
			}
		}
	}
}

// Reserve atomically records a nonce. It returns ErrAuthNonceReused if the
// nonce is still live; entries past their retention window are reclaimed.
//
// expires is the signed deadline. The record is retained until
// expires+authDeadlinePastSkew because ParseAuthNonceDeadline still accepts
// requests up to that skew; reclaiming at the raw deadline would reopen a
// replay window for captured requests (R2-02).
func (s *AuthReplayStore) Reserve(namespace string, addr types.Address, nonce string, expires time.Time) error {
	if err := validateReplayNonce(nonce); err != nil {
		return err
	}
	key := replayKey(namespace, addr, nonce)
	if len(key) > authReplayMaxKeyLen {
		return fmt.Errorf("replay key too long (%d bytes, max %d)", len(key), authReplayMaxKeyLen)
	}
	db, ok := s.beginOp()
	if !ok {
		return ErrAuthReplayStoreClosed
	}
	defer s.opMu.RUnlock()

	nowUnix := time.Now().Unix()
	expUnix := int64(0)
	if !expires.IsZero() {
		expUnix = expires.Add(authDeadlinePastSkew).Unix()
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		if b == nil {
			return fmt.Errorf("auth replay bucket missing")
		}
		if v := b.Get(expireKey(key)); v != nil {
			if exp, ok := decodeExpiry(v); !ok || exp == 0 || exp >= nowUnix {
				return ErrAuthNonceReused
			}
			if err := b.Delete(expireKey(key)); err != nil {
				return err
			}
		}
		if v := b.Get(permanentKey(key)); v != nil {
			_ = v
			return ErrAuthNonceReused
		}
		if expUnix == 0 {
			return b.Put(permanentKey(key), []byte{1})
		}
		return b.Put(expireKey(key), encodeExpiry(expUnix))
	})
}

// Prune deletes entries whose signed deadline has passed. Permanent entries
// (legacy nonces) are retained deliberately: replay protection for a signature
// without an expiry must not depend on a time window.
//
// Deletion is chunked: each write transaction removes at most
// authReplayPruneBatchSize entries so a large backlog does not monopolize the
// write lock and stall Reserve (R3-07).
func (s *AuthReplayStore) Prune(now time.Time) error {
	nowUnix := now.Unix()
	for {
		removed, err := s.pruneBatch(nowUnix, authReplayPruneBatchSize)
		if err != nil {
			return err
		}
		if removed < authReplayPruneBatchSize {
			return nil
		}
	}
}

// pruneBatch removes up to limit expired entries in one transaction and
// reports how many were deleted. A short batch means the bucket is drained.
func (s *AuthReplayStore) pruneBatch(nowUnix int64, limit int) (int, error) {
	removed := 0
	db, ok := s.beginOp()
	if !ok {
		return 0, ErrAuthReplayStoreClosed
	}
	defer s.opMu.RUnlock()

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(authReplayBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if !bytes.HasPrefix(k, expirePrefix) {
				continue
			}
			if exp, ok := decodeExpiry(v); ok && exp != 0 && exp < nowUnix {
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
				if removed >= limit {
					return nil
				}
			}
		}
		return nil
	})
	return removed, err
}

func replayKey(namespace string, addr types.Address, nonce string) string {
	return namespace + "|" + addr.ToHexAddress() + "|" + nonce
}

// validateReplayNonce bounds the client-controlled part of a replay record.
// The deadline-embedded namespaces enforce this inside ParseAuthNonceDeadline,
// but the governance namespace carries a free-form nonce next to an explicit
// deadline field, so the cap is applied at the replay boundary itself
// (R4-06): without it one key holder could store multi-kilobyte nonces per
// accepted request and grow the replay table (and its bbolt pages) at will.
func validateReplayNonce(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}
	if len(nonce) > authNonceMaxLen {
		return fmt.Errorf("nonce is too long (max %d bytes)", authNonceMaxLen)
	}
	return nil
}

func expireKey(key string) []byte {
	return append(append([]byte{}, expirePrefix...), []byte(key)...)
}

func permanentKey(key string) []byte {
	return append(append([]byte{}, permanentPrefix...), []byte(key)...)
}

func encodeExpiry(exp int64) []byte {
	return []byte(strconv.FormatInt(exp, 10))
}

func decodeExpiry(v []byte) (int64, bool) {
	exp, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return exp, true
}

// authReplayGuard binds an API namespace to either the persistent store or an
// in-memory fallback used by unit tests and standalone API construction.
type authReplayGuard struct {
	mu        sync.Mutex
	namespace string
	store     *AuthReplayStore
	entries   map[string]int64
	lastPrune time.Time
}

func newAuthReplayGuard(namespace string) *authReplayGuard {
	return &authReplayGuard{
		namespace: namespace,
		entries:   make(map[string]int64),
		lastPrune: time.Now(),
	}
}

func (g *authReplayGuard) setStore(store *AuthReplayStore) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.store = store
}

func (g *authReplayGuard) reserve(addr types.Address, nonce string, expires time.Time) error {
	if g == nil {
		return errAuthReplayGuardUnavailable
	}
	if err := validateReplayNonce(nonce); err != nil {
		return err
	}
	key := replayKey(g.namespace, addr, nonce)
	if len(key) > authReplayMaxKeyLen {
		return fmt.Errorf("replay key too long (%d bytes, max %d)", len(key), authReplayMaxKeyLen)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.store != nil {
		return g.store.Reserve(g.namespace, addr, nonce, expires)
	}

	now := time.Now()
	if now.Sub(g.lastPrune) >= time.Minute {
		g.pruneLocked(now)
		g.lastPrune = now
	}
	if exp, ok := g.entries[key]; ok {
		if exp == 0 || exp >= now.Unix() {
			return ErrAuthNonceReused
		}
		delete(g.entries, key)
	}
	exp := int64(0)
	if !expires.IsZero() {
		// Keep the entry through the +skew acceptance window (R2-02).
		exp = expires.Add(authDeadlinePastSkew).Unix()
	}
	g.entries[key] = exp
	return nil
}

func (g *authReplayGuard) pruneLocked(now time.Time) {
	nowUnix := now.Unix()
	for k, exp := range g.entries {
		if exp != 0 && exp < nowUnix {
			delete(g.entries, k)
		}
	}
}

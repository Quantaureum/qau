// Quantaureum Node source, version 1.0.0.
// Package common — R38-FOLLOWUP-5 race detector / lock-order production
// stopgap (2026-08-02).
//
// SECURITY.md:58 requires `-race` before submitting concurrent code, but
// the project's Windows build environment lacks gcc (mingw-w64), so
// CGO_ENABLED=1 go test -race cannot run there. The proper fix is to
// install mingw-w64; this file is a pure-Go stopgap that surfaces
// LOCK-ORDER VIOLATIONS (the most safety-critical concurrency defect the
// race detector would catch) via runtime assertions in builds that opt
// in via the LOCKORDER_DEBUG environment variable (or programmatically
// via common.SetLockOrderTracing(true)).
//
// THE WRAPPER DOES NOT REPLACE THE RACE DETECTOR. It catches a specific
// concurrency defect class — acquire-order cycles across mutexes — by
// tracking per-goroutine acquire stacks and asserting monotonic
// acquisition orders within a goroutine. The race detector additionally
// covers data-races on shared memory; the wrapper does NOT cover those.
// Operators / CI on a gcc-equipped host should still run `go test -race`.
// See plans/2026-08-01-r38-p2-and-verification.md §6 (Race detector).
//
// USAGE:
//
//	// In a long-lived object that has multiple coordinated mutexes:
//	// Replace
//	    mu1 sync.Mutex
//	    mu2 sync.Mutex
//	// with
//	    mu1 common.OrderedMutex
//	    mu2 common.OrderedMutex
//	    // initialize once:
//	    mu1.Init("db-state")
//	    mu2.Init("db-batch")
//	// On Lock, the wrapper auto-records (goroutine, lockID) and asserts
//	// the per-goroutine acquires are monotonic by lockID. Lock the
//	// higher-rank lock first; acquire the lower-rank lock second. Any
//	// out-of-order acquire fires a callback (default: panic with a clear
//	// stack-trace message).
//
// OPT-IN: the wrapper is OFF by default. To enable in tests:
//   - Set common.SetLockOrderTracing(true) in TestMain.
//   - Or set LOCKORDER_DEBUG=1 env var before process start.
//
// When disabled, Lock/Unlock are direct sync.Mutex pass-throughs (zero
// overhead).
package common

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

// lockOrderTracingEnabled is the global opt-in flag. Set via
// SetLockOrderTracing(true) or LOCKORDER_DEBUG=1. Atomic so callers can
// flip it at runtime.
var lockOrderTracingEnabled atomic.Bool

// lockOrderTracker records per-goroutine lock-acquire histories. The
// tracker is a single global map[goroutineID][]lockID — a goroutine's
// acquire stack. On each OrderedMutex.Lock() (when tracing is enabled),
// the wrapper asserts that no LOWER-rank lock is currently held by the
// same goroutine (i.e., acquires must be in increasing rank order).
var lockOrderTracker sync.Map // map[int64][]lockOrderEntry

// lockOrderOnViolation is the violation callback. Defaults to a
// stacktrace-panic so violations are loud. Tests can override to assert
// rather than panic (see common/lock_order_test.go).
var lockOrderOnViolation atomic.Pointer[func(violation LockOrderViolation)]

// lockOrderEntry records one held lock on a goroutine's stack.
type lockOrderEntry struct {
	lockID string // human-readable name (e.g., "db-state", "blockstore")
	rank   uint64 // acquire rank (lower = acquired earlier in the lock order)
}

// LockOrderViolation describes a detected lock-order inversion, passed to
// the violation callback so callers can record / panic / log.
type LockOrderViolation struct {
	// GoroutineID is the goroutine that committed the violation.
	GoroutineID int64
	// CulpritLock is the lock just acquired (lower rank than a held lock).
	CulpritLock string
	// CulpritRank is the rank of the lock just acquired.
	CulpritRank uint64
	// HeldLocks lists the locks the goroutine was already holding at the
	// time of the violation. The wrapper asserts none of these has a rank
	// GREATER than CulpritRank (i.e., culprit should be acquired first).
	HeldLocks []HeldLock
}

// HeldLock describes a single held lock at violation time.
type HeldLock struct {
	LockID string
	Rank   uint64
}

// SetLockOrderTracing toggles lock-order tracing. When true, every
// OrderedMutex.Lock records the acquire into a per-goroutine stack and
// checks for rank inversions; when false, Lock/Unlock are zero-overhead
// sync.Mutex pass-throughs. Configurable at any time (atomic store).
//
// R38-FOLLOWUP-5 (2026-08-02) race-detector stopgap.
func SetLockOrderTracing(enabled bool) {
	lockOrderTracingEnabled.Store(enabled)
}

// SetLockOrderViolationCallback installs a custom violation callback.
// Passing nil restores the default panic-with-stacktrace behavior.
// Tests use this to assert rather than panic.
func SetLockOrderViolationCallback(cb func(violation LockOrderViolation)) {
	if cb == nil {
		lockOrderOnViolation.Store(nil)
		return
	}
	// atomic.Pointer can't store a func value directly; we wrap it in
	// a synthesized closure-stable pointer via a sync.Pool-free
	// heap-allocated struct (resolving Go's "method value not addressable"
	// restriction).
	cbPtr := cb
	lockOrderOnViolation.Store(&cbPtr)
}

// IsLockOrderTracing reports whether tracing is currently enabled. Useful
// for tests + integrations that gate their own assertions on the
// wrapper's mode.
func IsLockOrderTracing() bool {
	return lockOrderTracingEnabled.Load()
}

// OrderedMutex is a sync.Mutex wrapper that records each Lock() into a
// per-goroutine acquire stack and asserts no LOWER-rank lock is currently
// held by the same goroutine. Ranks are assigned at Init() time and
// should reflect the canonical lock-acquire order (lower ranks acquired
// first). The wrapper is OPT-IN: with tracing off, Lock/Unlock are
// zero-overhead sync.Mutex pass-throughs.
//
// Use OrderedMutex only for coordinated mutex groups where there's a
// well-known acquire order (e.g., a state DB's mu + cacheMu, a P2P
// host's peersMu + handshakeSem). Do NOT use for one-off mutexes — that
// adds noise without acquiring a real invariant.
//
// R38-FOLLOWUP-5 (2026-08-02) race-detector stopgap.
type OrderedMutex struct {
	mu     sync.Mutex
	lockID string
	rank   uint64
	once   sync.Once
}

// Init assigns the lockID + rank. Calling Init more than once is a
// no-op (the first call wins). Idempotent so callers can Init in their
// constructor without a separate isInitialized flag. If never called,
// the wrapper falls back to lockID="" + rank=0 (no rank checking; the
// mutex behaves like a plain sync.Mutex).
func (om *OrderedMutex) Init(lockID string, rank uint64) {
	om.once.Do(func() {
		om.lockID = lockID
		om.rank = rank
	})
}

// Lock acquires the mutex. When tracing is enabled, records the acquire
// into the per-goroutine stack and asserts no held lock by the same
// goroutine has a HIGHER rank than this one (rank inversions = potential
// deadlock). On a detected violation, fires the configured callback
// (default: panic with a stacktrace).
func (om *OrderedMutex) Lock() {
	if !lockOrderTracingEnabled.Load() {
		om.mu.Lock()
		return
	}
	// Tracing path — record + assert BEFORE taking the underlying mutex
	// so the assertion runs unconditionally even if the Lock would block.
	gid := goroutineID()
	om.assertOrder(gid)
	om.mu.Lock()
	lockOrderTracker.Store(gid, append(lockOrderStackFor(gid), lockOrderEntry{
		lockID: om.lockID,
		rank:   om.rank,
	}))
}

// Unlock releases the mutex + pops the acquire from the per-goroutine
// stack. When tracing is disabled, this is a zero-overhead sync.Mutex
// pass-through.
func (om *OrderedMutex) Unlock() {
	om.mu.Unlock()
	if !lockOrderTracingEnabled.Load() {
		return
	}
	gid := goroutineID()
	stack := lockOrderStackFor(gid)
	// Pop the matching tail entry. We do a fair LIFO pop (the last-held
	// ent the wrapper pushed for THIS goroutine must be the one we're
	// now releasing).
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].lockID == om.lockID {
			newStack := make([]lockOrderEntry, 0, len(stack)-1)
			newStack = append(newStack, stack[:i]...)
			newStack = append(newStack, stack[i+1:]...)
			if len(newStack) == 0 {
				lockOrderTracker.Delete(gid)
			} else {
				lockOrderTracker.Store(gid, newStack)
			}
			break
		}
	}
}

// TryLock attempts to acquire the lock without blocking. Returns true if
// acquired. When tracing is enabled, records the acquire on success.
func (om *OrderedMutex) TryLock() bool {
	if !om.mu.TryLock() {
		return false
	}
	if lockOrderTracingEnabled.Load() {
		gid := goroutineID()
		// Best-effort order check (TryLock is racy by definition; we
		// don't assert before Take because there's no pre-acquire path).
		// We DO record the acquire so subsequent acquires by the same
		// goroutine can still assert.
		lockOrderTracker.Store(gid, append(lockOrderStackFor(gid), lockOrderEntry{
			lockID: om.lockID,
			rank:   om.rank,
		}))
	}
	return true
}

// assertOrder checks the per-goroutine acquire stack for a lock-order
// inversion. A violation is triggered when a held lock has rank GREATER
// than this mutex's rank (i.e., we're acquiring a LOWER-rank mutex while
// holding a HIGHER-rank one — potential deadlock if another goroutine
// takes them in the canonical rank-ascending order).
//
// Zero-rank mutexes (Init was never called) skip the rank check.
func (om *OrderedMutex) assertOrder(gid int64) {
	if om.rank == 0 || om.lockID == "" {
		return
	}
	stack := lockOrderStackFor(gid)
	var held []HeldLock
	for _, ent := range stack {
		if ent.rank == 0 {
			continue // unranked lock on the goroutine stack — skip
		}
		if ent.rank > om.rank {
			held = append(held, HeldLock{
				LockID: ent.lockID,
				Rank:   ent.rank,
			})
		}
	}
	if len(held) == 0 {
		return
	}
	violation := LockOrderViolation{
		GoroutineID: gid,
		CulpritLock: om.lockID,
		CulpritRank: om.rank,
		HeldLocks:   held,
	}
	fireViolation(violation)
}

// fireViolation dispatches to the configured callback; if none, panics
// with a stacktrace so the violation is loud.
func fireViolation(v LockOrderViolation) {
	cb := lockOrderOnViolation.Load()
	if cb != nil {
		(*cb)(v)
		return
	}
	// Default: panic with a clear, actionable message.
	// Test runners can assert the panic by installing a callback that
	// instead records the violation into a slice channel.
	heldSummary := ""
	for _, h := range v.HeldLocks {
		heldSummary += "\n  - " + h.LockID + " (rank=" + uintToString(h.Rank) + ")"
	}
	panic("LOCK-ORDER VIOLATION (R38-FOLLOWUP-5): goroutine " + int64ToString(v.GoroutineID) +
		" acquired \"" + v.CulpritLock + "\" (rank=" + uintToString(v.CulpritRank) + ")" +
		" while holding HIGHER-rank lock(s):" + heldSummary +
		"\n  Canonical acquire order is increasing rank. Reorder acquires or Init() with higher rank for \"" +
		v.CulpritLock + "\".")
}

// lockOrderStackFor returns the per-goroutine acquire stack (or nil).
func lockOrderStackFor(gid int64) []lockOrderEntry {
	if v, ok := lockOrderTracker.Load(gid); ok {
		if s, ok := v.([]lockOrderEntry); ok {
			return s
		}
	}
	return nil
}

// ResetLockOrderStacksForTesting clears the tracker state. Used in tests
// to ensure clean slate between subtests.
func ResetLockOrderStacksForTesting() {
	// sync.Map has no Reset/Clear; iterate + delete.
	lockOrderTracker.Range(func(k, _ any) bool {
		lockOrderTracker.Delete(k)
		return true
	})
}

// goroutineID returns a 64-bit goroutine identifier obtained via the
// runtime's stack base pointer. We use runtime.Stack to extract the
// "goroutine N [" prefix. This is stable across Go versions and avoids
// the undocument runtime.Goid hack.
func goroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// buf now contains "goroutine N [status]:\n..."
	// Extract N until first space.
	s := string(buf[:n])
	const prefix = "goroutine "
	if len(s) <= len(prefix) {
		return 0
	}
	s = s[len(prefix):]
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	var id int64
	for i := 0; i < end; i++ {
		id = id*10 + int64(s[i]-'0')
	}
	return id
}

// uintToString avoids importing strconv + fmt just for one conversion.
// We inline a minimal base-10 itoa.
func uintToString(n uint64) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// int64ToString is the signed counterpart.
func int64ToString(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// init reads the LOCKORDER_DEBUG env var at package initialization so
// operators (or CI) can enable tracing without modifying code.
func init() {
	if os.Getenv("LOCKORDER_DEBUG") != "" {
		lockOrderTracingEnabled.Store(true)
	}
}

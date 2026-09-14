// Quantaureum Node source, version 1.0.0.
package node

import (
	"sync"
	"time"
)

// R87-STATE-TRUST (2026-08-29)
//
// Problem this solves
// -------------------
// A node whose local state has diverged from the network kept producing and
// validating blocks indefinitely. Two independent fail-open paths combined:
//
//  1. node.go SetOnForkRollback: after a fork is accepted the syncer deletes
//     the abandoned blocks and then the callback rolls the stateDB back. If
//     RollbackToHeight fails (R39-P2-02 returns an error when the target height
//     is below the retained beforeImage window) the code logged ERROR and
//     CONTINUED. The blocks were already gone, so the node now had chain
//     history for one branch and account state for another — permanently.
//
//  2. syncer.go applyBlockInternal: with strictStateRoot disabled
//     (R63-STATE-ROOT-TRUST, the M4 workaround) a state-root mismatch logs a
//     WARN, trusts the header root and advances. That is a deliberate liveness
//     choice, but it had NO upper bound and NO consumer for the
//     stateRootMismatches counter, so divergence was invisible.
//
// In a diverged multi-node replay, the same height can carry different block
// hashes and the same account can report different balances because a
// transaction was committed on one branch but not another. The trust break
// turns that silent divergence into an explicit degraded state.
//
// Design
// ------
// Once local state can no longer be trusted, the node must stop PRODUCING
// blocks (safety) while still following the network (liveness). Producing is
// the only action that pushes local divergence onto peers, so it is the one
// action worth blocking. We deliberately do NOT auto-trigger rebuildState:
// R63 documented a rebuild↔resync death loop when the post-rebuild root still
// mismatches, and an automatic loop there would be worse than a node that
// follows quietly and reports itself as degraded.
//
// Two triggers:
//   - a failed fork rollback (hard, immediate — state is known-inconsistent)
//   - consecutive state-root mismatches beyond stateTrustMismatchStreakLimit
//     (soft, evidence-based — a healthy node shows a 0-length streak)
//
// A single matching state root clears the soft streak; only an operator action
// (re-sync, restart) clears a hard break.
const stateTrustMismatchStreakLimit = 32

// stateTrustReason describes why local state stopped being trustworthy.
type stateTrustReason struct {
	// Detail is a human-readable explanation for logs and RPC.
	Detail string
	// At is when the break was recorded.
	At time.Time
	// Hard is true for a known-inconsistent state (failed rollback) and false
	// for evidence-based suspicion (mismatch streak).
	Hard bool
}

// stateTrust tracks whether this node's local state can still be trusted to
// derive blocks. Safe for concurrent use.
type stateTrust struct {
	mu             sync.RWMutex
	broken         *stateTrustReason
	mismatchStreak int
	// streakLimit is configurable so tests do not have to loop 32 times.
	streakLimit int
}

func newStateTrust() *stateTrust {
	return &stateTrust{streakLimit: stateTrustMismatchStreakLimit}
}

// breakHard marks the state as known-inconsistent. Idempotent: the first
// reason is kept so operators see the original cause. Returns true if this
// call is the one that broke trust.
func (t *stateTrust) breakHard(detail string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken != nil {
		return false
	}
	t.broken = &stateTrustReason{Detail: detail, At: time.Now(), Hard: true}
	return true
}

// recordMismatch counts one state-root mismatch. Returns true if this call
// crossed the streak limit and broke trust.
func (t *stateTrust) recordMismatch(detail string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mismatchStreak++
	if t.broken != nil || t.mismatchStreak < t.streakLimit {
		return false
	}
	t.broken = &stateTrustReason{Detail: detail, At: time.Now(), Hard: false}
	return true
}

// recordMatch resets the mismatch streak. A hard break is NOT cleared: a
// failed rollback leaves state inconsistent in ways a single agreeing root
// cannot disprove.
func (t *stateTrust) recordMatch() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mismatchStreak = 0
	if t.broken != nil && !t.broken.Hard {
		t.broken = nil
	}
}

// ok reports whether local state is still trusted.
func (t *stateTrust) ok() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.broken == nil
}

// reason returns a copy of the break reason, or nil when trust is intact.
func (t *stateTrust) reason() *stateTrustReason {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.broken == nil {
		return nil
	}
	r := *t.broken
	return &r
}

// streak returns the current consecutive-mismatch count (diagnostics).
func (t *stateTrust) streak() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mismatchStreak
}

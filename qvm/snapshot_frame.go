package qvm

// Per-frame state journaling helpers.
//
// R4-08 (2026-10-21 audit). Every call frame (CALL/CALLCODE/DELEGATECALL/
// STATICCALL/CREATE/AUTHCALL and their JIT equivalents) journals a state
// snapshot so the frame can be rolled back when the sub-call fails. Until now
// the entry was only consumed when the frame reverted, so each SUCCESSFUL
// sub-call leaked one entry onto the StateDB snapshot stack for the whole
// transaction. A contract that loops over external calls therefore exhausted
// state.maxSnapshotDepth inside a single transaction (roughly 1024 calls, well
// inside a 30M-gas transaction), after which Snapshot() began returning the
// -1 depth sentinel and:
//
//   - later frames executed unjournaled, so their failures could not be rolled
//     back (state changes from a reverted sub-call became permanent), and
//   - a failure that still called RevertToSnapshot(-1) rewound the whole
//     in-flight frame chain instead of just the failing frame.
//
// Both are deterministic (every validator computes the same wrong state), so
// the impact is silent state loss rather than a fork, which makes them harder
// to notice.
//
// The fix keeps the journal bounded by the LIVE call depth: a frame that
// finished successfully releases its entry, and a frame that could not journal
// at all refuses the call the same way it refuses one past MaxCallDepth.

// snapshotReleaser is implemented by backing state stores that can discard a
// completed frame's journal entries without rewinding state
// (*state.StateDB and the adapters that wrap it).
type snapshotReleaser interface {
	ReleaseSnapshot(id int)
}

// releaseFrame discards the journal entry taken for a call frame that finished
// successfully, together with any entries the frame's own sub-calls left
// behind. Backings without a release primitive keep the entry, which preserves
// the previous behavior for test doubles and read-only RPC state stubs.
func releaseFrame(db StateDB, id int) {
	if id < 0 || db == nil {
		return
	}
	if releaser, ok := db.(snapshotReleaser); ok {
		releaser.ReleaseSnapshot(id)
	}
}

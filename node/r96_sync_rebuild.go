// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"sync/atomic"

	"github.com/quantaureum/qau/types"
)

// R96-SYNCFLAP / R97-UNVALIDATED-LEAK / R98-LOGLIE (2026-08-30)
//
// Three defects in the post-sync rebuild lifecycle:
// unnecessary rebuild scheduling, durable unvalidated-marker leakage, and a
// misleading root-validation log message.
//
// They are grouped in one file because they share a single origin: the rebuild
// path was designed for the "node joins and catches up" case, and nobody
// revisited its triggering or its log wording once P3-SYNC-GATE made brief sync
// mode a once-per-slot event during NORMAL operation.
//
// Kept as free functions so the decision logic is testable without standing up
// a Syncer, a block store, a state DB and a peer set.

// shouldRebuildAfterSync reports whether checkSync should launch rebuildState
// after the node transitions from syncing to caught-up.
//
// THE STORM:
//
// P3-SYNC-GATE (syncer.go ~2196) deliberately treats ANY gap >= 1 as sync mode
// to prevent same-height forks — that part is correct and must not change. But
// with 6 validators taking turns, every non-proposing node is one block behind
// for part of every 12 s slot, so s.syncing legitimately flips true→false once
// per slot forever. The old trigger asked only "were we syncing?" and never "is
// there an unverified range?", so it re-applied the chain tip on top of state
// that already contained it, once per slot, per node, indefinitely.
//
// Nothing breaks immediately, because computeRebuildBaseline
// (R87-M4-ROOTCAUSE) clamps the baseline and prevents double-crediting epoch
// rewards. But a guard that exists to make an unnecessary operation survivable
// is not a license to keep performing it: the storm costs one goroutine and one
// state re-application per slot, and its log volume can hide the R97 leak below.
//
// THE RULE, and why it is not a height comparison.
//
// A height-only gate is insufficient: a node can briefly sit at
// verified == head-1 after receiving the tip through the validated path, while
// another node can have the same height gap because its tip bypassed
// validation.
//
// A height margin cannot separate the two cases because they can share the same
// heights. What actually distinguishes them is HOW the intervening blocks were
// applied:
//
//	normal tip arrival: the tip arrived via ProcessBlock → applyBlock with
//	                   strictStateRoot=true, so its root was already proven.
//	                   No unvalidated marker exists. Nothing to rebuild.
//	genuine catch-up:  blocks were persisted by the sync path, which skips
//	                   per-block root validation and marks each one
//	                   unvalidated. Those markers ARE the work list.
//
// So the trigger asks the authoritative question directly: does the range
// (stateVerifiedHeight, currentHeight] contain any block that was persisted
// without having its root proven? This is the same map that rebuildRange
// drains, which makes the trigger and the work it schedules agree by
// construction rather than by coincidence.
func shouldRebuildAfterSync(wasSyncing bool, currentHeight, stateVerifiedHeight uint64, unvalidatedInRange int) bool {
	if !wasSyncing {
		// Arming happens on the syncing→caught-up transition only.
		return false
	}
	if currentHeight == 0 {
		// Genesis-only chain: rebuildState would return immediately anyway.
		return false
	}
	if stateVerifiedHeight >= currentHeight {
		// Fully verified through the head, or verified AHEAD of it after a
		// rollback — re-applying committed blocks would be actively harmful.
		return false
	}
	// Verified height is behind the head, but that alone is ambiguous. Only
	// rebuild if something in the gap actually bypassed
	// validation.
	return unvalidatedInRange > 0
}

// countUnvalidatedInRange returns how many unvalidated-block markers fall in
// (lowExclusive, highInclusive] — the blocks a rebuild would actually need to
// re-apply and prove. Caller must hold s.mu (read or write).
func (s *Syncer) countUnvalidatedInRangeLocked(lowExclusive, highInclusive uint64) int {
	n := 0
	for _, height := range s.unvalidatedBlocks {
		if height > lowExclusive && height <= highInclusive {
			n++
		}
	}
	return n
}

// classifyUnvalidatedMarkers partitions surviving unvalidated-block markers by
// their position relative to the range a rebuild just covered.
//
// THE LEAK: ProcessBlock marks every sync-persisted block unvalidated;
// rebuildRange clears markers only for heights inside [fromHeight, toHeight].
// startHeight rises after every restart, so markers below the new fromHeight
// are never visited again. They are persisted to the block store, restored on
// the next boot, and can accumulate monotonically:
//
// Why it matters despite IsCanonicalUnvalidated having no production callers:
// maxUnvalidatedBlocks (100000) is a fail-CLOSED cap — ProcessBlock returns an
// error and aborts sync on reaching it. A monotonic leak pointed at a
// fail-closed cap is a latent outage, however far away.
//
// Why the old single total was actively misleading: it was logged as "blocks
// still marked unvalidated after rebuild (failed re-application)", even though
// markers stranded below the rebuild range never failed re-application. The
// message attributed the survivors to the wrong subsystem.
//
// Returns (stranded, inRange, ahead):
//   - stranded: height < fromHeight — unreachable by any future rebuild; leaking
//   - inRange:  fromHeight <= height <= toHeight — genuine re-application failures
//   - ahead:    height > toHeight — benign, a later rebuild covers them
func classifyUnvalidatedMarkers(markers map[types.Hash]uint64, fromHeight, toHeight uint64) (stranded, inRange, ahead int) {
	for _, height := range markers {
		switch {
		case height < fromHeight:
			stranded++
		case height > toHeight:
			ahead++
		default:
			inRange++
		}
	}
	return stranded, inRange, ahead
}

// markersDrainedByVerifiedRoot returns the unvalidated-block markers that a
// successful final root verification at verifiedHeight has proven, and which
// must therefore be cleared.
//
// R97b-UNVALIDATED-DRAIN (2026-08-30): the first R97 change only made the leak
// visible (stranded / in-range / ahead). Visibility is not a fix, because every
// restart can raise startHeight and abandon the previous window's markers,
// while rebuildRange only clears inside [from, to].
//
// WHY DRAINING IS SOUND. Chain state is cumulative: the state root at height N
// commits to the result of applying every block from genesis through N. So when
// rebuildRange's final check reports
//
//	"state root verified at block N (computed == header)"
//
// it has proven not just block N but the whole state-transition chain up to N.
// A marker at height <= N records a doubt that this verification has resolved;
// keeping it makes the fail-closed surface lie in the pessimistic direction and
// leaks toward maxUnvalidatedBlocks (100000), which aborts sync when reached.
// This is the same cumulative-root reasoning R63-STATE-ROOT-TRUST already uses
// when it decides a canonical root may be trusted.
//
// Markers ABOVE N are preserved: nothing has proven those blocks, and clearing
// them would convert a fail-closed surface into a false all-clear.
//
// Returns a map so the caller can delete from both the in-memory set and the
// durable store without holding s.mu across disk I/O.
func markersDrainedByVerifiedRoot(markers map[types.Hash]uint64, verifiedHeight uint64) map[types.Hash]uint64 {
	drained := make(map[types.Hash]uint64)
	for h, height := range markers {
		if height <= verifiedHeight {
			drained[h] = height
		}
	}
	return drained
}

// skippedStateRootReason renders the explanation attached to the two ERROR
// lines emitted when a state-root comparison is bypassed.
//
// THE LIE: the previous text was
//
//	"(strictStateRoot=false). This masks the M4 root-derivation discrepancy.
//	 Enable SetStrictStateRoot(true) after fixing M4 to reject invalid blocks."
//
// Every clause misdescribes the situation in which it actually fires:
//   - strictStateRoot defaults to TRUE (syncer.go:393, audit HIGH-01) and
//     SetStrictStateRoot has ZERO production callers, so it is never false on a
//     real node;
//   - the bypass comes from the per-call skipStateRootValidation argument, which
//     rebuildRange passes as true BY DESIGN because rebuildState verifies the
//     final root once at the end (R32-P1-02) instead of per block;
//   - so it instructed the operator to flip a setting that was already correct,
//     to fix a cause that did not apply.
//
// A log line that invents a vulnerability wastes more time than no log line at
// all.
func skippedStateRootReason(duringRebuild bool) string {
	if duringRebuild {
		return fmt.Sprintf("bypassed by design during state rebuild (rebuildRange passes "+
			"skipStateRootValidation=true); the reconstructed root is verified once against the "+
			"canonical header at the end of the rebuild (R32-P1-02). strictStateRoot is unaffected "+
			"and remains %v. No action required unless the final post-rebuild verification also fails.", true)
	}
	return "state-root comparison was bypassed OUTSIDE a rebuild — this is a genuine fail-open: " +
		"the block was accepted without proving its state root. Investigate immediately; " +
		"strictStateRoot should be true (default) and no production code disables it."
}

// isRebuilding reports whether a rebuildState worker is currently running, so
// skippedStateRootReason can tell the by-design bypass apart from a real
// fail-open. Reads the same atomic that rebuildState's CAS guard owns.
func (s *Syncer) isRebuilding() bool {
	return atomic.LoadInt32(&s.rebuildRunning) == 1
}

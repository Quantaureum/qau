// Quantaureum Node source, version 1.0.0.
package node

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R96/R97/R98 — three defects in the Syncer's post-sync rebuild lifecycle:
// unnecessary rebuild scheduling, durable unvalidated-marker leakage, and a
// misleading root-validation log message.

// ---------------------------------------------------------------------------
// R96-SYNCFLAP
// ---------------------------------------------------------------------------

// TestR96_NoRebuildWhenStateAlreadyVerified pins the guard that stops the
// rebuild storm.
//
// ROOT CAUSE: P3-SYNC-GATE (syncer.go ~2196) deliberately treats ANY gap >= 1
// as sync mode, to prevent same-height forks. With 6 validators taking turns,
// every non-proposing node is one block behind for part of every slot, so
// `s.syncing` legitimately flips true→false once per 12 s. checkSync then sees
// `wasSyncing == true` and unconditionally fires
// `go s.rebuildState(s.startHeight, s.currentHeight)`.
//
// The trigger only asks "were we syncing a moment ago?" and never "is there
// actually any unverified range to rebuild?". Since stateVerifiedHeight is
// already at the tip during normal operation, the answer is almost always no.
//
// Consequences (none of them immediately fatal):
//   - one goroutine + one state re-application per slot per node, forever
//   - the newest block is re-applied on top of state that already contains it;
//     only computeRebuildBaseline (R87-M4-ROOTCAUSE) keeps that from
//     double-crediting epoch rewards. A guard protecting against something
//     that should never be attempted is not a reason to keep attempting it.
//   - three log lines per slot, which is what buried the R97 leak below: the
//     genuine "unvalidated markers are accumulating" signal was
//     indistinguishable from routine chatter.
//
// FIX: shouldRebuildAfterSync — only rebuild when the verified height is
// actually behind the chain head.
func TestR96_NoRebuildWhenStateAlreadyVerified(t *testing.T) {
	tests := []struct {
		name                string
		wasSyncing          bool
		currentHeight       uint64
		stateVerifiedHeight uint64
		unvalidatedInRange  int
		want                bool
		why                 string
	}{
		{
			name: "steady state single-slot flap must NOT rebuild",
			// The node was briefly one block behind, then caught up. The tip
			// arrived through the normal validated path, so it left no marker.
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 499, unvalidatedInRange: 0,
			want: false,
			why: "verified == head-1 with nothing unvalidated must not rebuild; " +
				"a height-margin gate would still fire here",
		},
		{
			name:       "verified exactly at head must NOT rebuild",
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 500, unvalidatedInRange: 0,
			want: false,
			why:  "state is fully verified through the head",
		},
		{
			name:       "verified ahead of head must NOT rebuild",
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 620, unvalidatedInRange: 3,
			want: false,
			why: "a rollback left verified ahead; re-applying committed blocks would be harmful " +
				"even though markers exist",
		},
		{
			name: "genuine catch-up MUST rebuild",
			// Real sync: joined at 0, pulled 500 blocks via the sync path,
			// every one of them marked unvalidated.
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 0, unvalidatedInRange: 500,
			want: true,
			why:  "500 blocks were persisted during sync without per-block root validation",
		},
		{
			name:       "partial catch-up MUST rebuild",
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 450, unvalidatedInRange: 50,
			want: true,
			why:  "blocks 451..500 came from the sync path and are still unproven",
		},
		{
			name: "single genuinely unvalidated tip MUST rebuild",
			// Same heights as the storm case, but the tip really did bypass
			// validation. Must NOT be swallowed by the fix.
			wasSyncing: true, currentHeight: 500, stateVerifiedHeight: 499, unvalidatedInRange: 1,
			want: true,
			why: "the fix must key on the marker, not on the height margin, or it would " +
				"silently skip proving a block that bypassed validation",
		},
		{
			name:       "not previously syncing must NOT rebuild",
			wasSyncing: false, currentHeight: 500, stateVerifiedHeight: 0, unvalidatedInRange: 500,
			want: false,
			why:  "the transition into 'caught up' is what arms the rebuild",
		},
		{
			name:       "zero head must NOT rebuild",
			wasSyncing: true, currentHeight: 0, stateVerifiedHeight: 0, unvalidatedInRange: 0,
			want: false,
			why:  "genesis-only chain has nothing to rebuild",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRebuildAfterSync(tc.wasSyncing, tc.currentHeight, tc.stateVerifiedHeight, tc.unvalidatedInRange)
			if got != tc.want {
				t.Errorf("shouldRebuildAfterSync(wasSyncing=%v, cur=%d, verified=%d, unvalidated=%d) = %v, want %v\nreason: %s",
					tc.wasSyncing, tc.currentHeight, tc.stateVerifiedHeight, tc.unvalidatedInRange, got, tc.want, tc.why)
			}
		})
	}
}

// TestR96_SteadyStateFlapDoesNotAccumulateRebuilds simulates 32 consecutive
// single-slot flaps (one epoch) and asserts not a single rebuild is armed.
// Before the fix this yields 32 unnecessary rebuilds.
func TestR96_SteadyStateFlapDoesNotAccumulateRebuilds(t *testing.T) {
	const slots = 32
	rebuilds := 0
	verified := uint64(1000)
	for i := range uint64(slots) {
		head := 1001 + i // chain advances one block per slot
		// The node was briefly one block behind, then caught up. The tip came
		// through ProcessBlock → applyBlock with strictStateRoot=true, so it
		// left no unvalidated marker.
		if shouldRebuildAfterSync(true, head, verified, 0) {
			rebuilds++
		}
		verified = head
	}
	if rebuilds != 0 {
		t.Errorf("armed %d rebuilds across %d steady-state slot flaps, want 0 "+
			"(R96 storm)", rebuilds, slots)
	}
}

// ---------------------------------------------------------------------------
// R97-UNVALIDATED-LEAK
// ---------------------------------------------------------------------------

// TestR97_UnvalidatedMarkersOutsideRebuildRangeAreReported documents and pins
// a genuine monotonic leak.
//
// Consider a sequence of restart windows with increasing rebuild start
// heights. Markers below each new start height can never be visited again.
// ProcessBlock marks every sync-persisted block unvalidated. rebuildRange
// clears markers only for blocks inside [fromHeight, toHeight]. After a
// restart, startHeight advances, so markers below the new fromHeight are never
// visited again — they persist to disk, get restored on the next boot, and
// accumulate forever.
//
// Two consequences:
//  1. maxUnvalidatedBlocks (100000) is a fail-CLOSED cap: on reaching it
//     ProcessBlock returns an error and aborts sync. A monotonic leak against
//     a fail-closed cap is a latent outage, however distant.
//  2. The WARN's own explanation was wrong. It claims the survivors "failed
//     re-application (counted in `failed`)", but stranded markers never
//     reached re-application at all.
//
// FIX: classifyUnvalidatedMarkers splits survivors by position relative to the
// rebuilt range so the operator learns which ones are benign (ahead of the
// range, not yet rebuilt) and which are stranded (below it, unreachable and
// leaking).
func TestR97_UnvalidatedMarkersOutsideRebuildRangeAreReported(t *testing.T) {
	markers := map[types.Hash]uint64{
		{0x01}: 100, // stranded: below fromHeight, no future rebuild reaches it
		{0x02}: 250, // stranded
		{0x03}: 500, // inside the rebuilt range → genuine re-application failure
		{0x04}: 900, // ahead of toHeight → benign, a later rebuild covers it
		{0x05}: 950, // ahead → benign
	}

	stranded, inRange, ahead := classifyUnvalidatedMarkers(markers, 400, 800)

	if stranded != 2 {
		t.Errorf("stranded = %d, want 2 (heights 100 and 250 sit below fromHeight=400 and "+
			"no future rebuild will ever visit them — this is the R97 leak)", stranded)
	}
	if inRange != 1 {
		t.Errorf("inRange = %d, want 1 (height 500 is the only true re-application failure)", inRange)
	}
	if ahead != 2 {
		t.Errorf("ahead = %d, want 2 (heights 900 and 950 are simply not rebuilt yet — benign)", ahead)
	}
}

// TestR97_LeakGrowsAcrossRestartsWithoutClassification shows that each restart
// can raise fromHeight and strand the previous window's markers permanently.
func TestR97_LeakGrowsAcrossRestartsWithoutClassification(t *testing.T) {
	restarts := []struct{ from, to uint64 }{
		{0, 99},
		{100, 199},
		{200, 299},
		{300, 499},
	}

	markers := map[types.Hash]uint64{}
	next := byte(1)
	strandedFinal := 0

	for _, r := range restarts {
		// Each sync window persists a few blocks whose roots were never
		// re-verified (empty blocks skipped by the producer path).
		for range 4 {
			markers[types.Hash{next}] = r.from + 1
			next++
		}
		stranded, _, _ := classifyUnvalidatedMarkers(markers, r.from, r.to)
		strandedFinal = stranded
	}

	if strandedFinal == 0 {
		t.Fatal("expected stranded markers to accumulate across restarts; " +
			"classifyUnvalidatedMarkers must expose them so the leak is visible")
	}
	// 3 prior windows x 4 markers each are below the final fromHeight=300.
	if strandedFinal != 12 {
		t.Errorf("stranded after 4 restart windows = %d, want 12 — the leak must be "+
			"attributed to prior windows, not to re-application failures", strandedFinal)
	}
}

// ---------------------------------------------------------------------------
// R98-LOGLIE
// ---------------------------------------------------------------------------

// TestR98_SkippedRootMessageMustNotBlameStrictStateRoot pins the wording of the
// two ERROR lines emitted when a state-root check is bypassed.
//
// The old text was:
//
//	"State root validation SKIPPED for block %d (strictStateRoot=false).
//	 ... Enable SetStrictStateRoot(true) after fixing M4 ..."
//
// Every clause of that is wrong in the situation where it actually fires:
//   - strictStateRoot defaults to TRUE (syncer.go:393, audit HIGH-01) and has
//     ZERO production callers of SetStrictStateRoot, so it is never false on a
//     real node.
//   - the bypass comes from the per-call skipStateRootValidation argument that
//     rebuildRange passes as `true` BY DESIGN (rebuildState verifies the final
//     root once at the end instead of per block).
//   - so it tells the operator to flip a setting that is already correct, for a
//     reason that does not apply.
//
// A log line that invents a vulnerability is worse than silence.
//
// FIX: name the real mechanism (rebuild-phase bypass) and state that the final
// root is verified at the end of the rebuild.
func TestR98_SkippedRootMessageMustNotBlameStrictStateRoot(t *testing.T) {
	msg := skippedStateRootReason(true)

	if strings.Contains(msg, "strictStateRoot=false") {
		t.Errorf("message still blames strictStateRoot=false: %q\n"+
			"strictStateRoot defaults to true and has no production setter; "+
			"the bypass is the rebuild-phase skipStateRootValidation argument", msg)
	}
	if strings.Contains(msg, "SetStrictStateRoot(true)") {
		t.Errorf("message still tells the operator to enable an already-enabled setting: %q", msg)
	}
	if !strings.Contains(msg, "rebuild") {
		t.Errorf("message must name the actual mechanism (rebuild-phase bypass): %q", msg)
	}

	// The non-rebuild caller must keep a genuinely alarming message: if a root
	// check is skipped outside a rebuild, that IS a real fail-open.
	direct := skippedStateRootReason(false)
	if direct == msg {
		t.Error("the rebuild-phase and non-rebuild reasons must differ; " +
			"a bypass outside a rebuild is a real fail-open and must not be described as routine")
	}
}

// ---------------------------------------------------------------------------
// R97b-UNVALIDATED-DRAIN — closing the leak instead of only reporting it
// ---------------------------------------------------------------------------

// TestR97b_VerifiedRootDrainsAllMarkersAtOrBelowHeight pins the fix that
// actually eliminates the leak.
//
// The first R97 change made the leak visible (stranded vs in-range vs ahead).
// Visibility is not a fix: every restart can raise startHeight and abandon the
// previous window's markers.
//
// WHY THEY CAN BE DRAINED. Chain state is cumulative: the state root at height
// N is a commitment to the result of applying every block from genesis through
// N. So when rebuildRange's final check reports
//
//	"state root verified at block N (computed == header)"
//
// it has proven not merely block N but the entire state transition chain up to
// N. Any marker at height <= N is therefore stale by construction — the doubt
// it records has been resolved. This is the same reasoning R63-STATE-ROOT-TRUST
// already relies on when it decides a canonical root may be trusted.
//
// Markers ABOVE N must be preserved: nothing has proven them yet.
//
// Fails without the fix: markers below the rebuilt range survive forever,
// accumulate across restarts, and creep toward maxUnvalidatedBlocks (100000),
// which is a fail-CLOSED cap that aborts sync when reached.
func TestR97b_VerifiedRootDrainsAllMarkersAtOrBelowHeight(t *testing.T) {
	markers := map[types.Hash]uint64{
		{0x01}: 5,   // stranded from an early window
		{0x02}: 100, // stranded
		{0x03}: 231, // stranded from an earlier rebuild window
		{0x04}: 500, // inside the rebuilt range
		{0x05}: 800, // == toHeight, proven
		{0x06}: 801, // above toHeight — must survive
		{0x07}: 900, // above — must survive
	}

	drained := markersDrainedByVerifiedRoot(markers, 800)

	if len(drained) != 5 {
		t.Errorf("drained %d markers, want 5 (heights 5, 100, 231, 500, 800 are all at or below "+
			"the verified height and are proven by the cumulative state root)", len(drained))
	}
	for _, h := range []types.Hash{{0x01}, {0x02}, {0x03}, {0x04}, {0x05}} {
		if _, ok := drained[h]; !ok {
			t.Errorf("marker %x at or below the verified height was not drained — this is the "+
				"R97 leak: no future rebuild will ever revisit it", h[:1])
		}
	}
	for _, h := range []types.Hash{{0x06}, {0x07}} {
		if _, ok := drained[h]; ok {
			t.Errorf("marker %x is ABOVE the verified height and must NOT be drained — "+
				"nothing has proven those blocks yet, and clearing them would turn a "+
				"fail-closed surface into a false all-clear", h[:1])
		}
	}
}

// TestR97b_LeakDoesNotAccumulateAcrossRestarts replays generic restart windows
// and asserts the stranded count returns to zero once each rebuild verifies
// its root — the property the reporting-only change did not provide.
func TestR97b_LeakDoesNotAccumulateAcrossRestarts(t *testing.T) {
	restarts := []struct{ from, to uint64 }{
		{0, 231},
		{232, 257},
		{258, 400},
		{401, 600},
	}

	markers := map[types.Hash]uint64{}
	next := byte(1)

	for _, r := range restarts {
		// Each window persists blocks via the sync path, marking them.
		for h := r.from; h <= r.to && h < r.from+4; h++ {
			markers[types.Hash{next}] = h
			next++
		}
		// The rebuild verifies its final root, which proves everything <= to.
		for h := range markersDrainedByVerifiedRoot(markers, r.to) {
			delete(markers, h)
		}
		stranded, _, _ := classifyUnvalidatedMarkers(markers, r.from, r.to)
		if stranded != 0 {
			t.Errorf("after window %d..%d: %d stranded markers remain, want 0 — "+
				"draining on verified root must leave nothing behind for the next restart "+
				"to abandon (R97b)", r.from, r.to, stranded)
		}
	}
	if len(markers) != 0 {
		t.Errorf("%d markers survived all four windows, want 0", len(markers))
	}
}

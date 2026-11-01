// Quantaureum Node source, version 1.0.0.
package node

// R33 (2026-11-01) — deep-integrity background pass.
//
// The startup continuity scan (R32c) verifies parent linkage for the LAST
// continuityParentWindow (64) heights only: decoding every 30KB header on a
// 337k chain made Node.Start unaffordable (the fleet freeze R32-01). This
// pass covers the WHOLE chain after the node is fully up, in segments of
// verifySegmentHeights heights — each segment is its own bbolt read
// transaction, so mmap-growth and DB-close waits are bounded by one segment
// (~seconds) and no store lock is ever taken.
//
// Deep linkage damage (a header that is missing, undecodable, or fails to
// link to its parent — legacy stores predating the 2026-08-17 write rules,
// or bit rot) cannot be auto-repaired while the node is running: a live
// truncation would need the F14/F19 three-witness discipline at arbitrary
// depth. Detection therefore FAILS CLOSED — production stops and the
// operator rebuilds via the hardened debug rollback (R30 F14-F19). The node
// keeps FOLLOWING the chain (reads and sync are unaffected); only block
// production is gated. A number-index GAP is reported separately (WARN,
// pass stops): a mid-delete snapshot is always a gapless prefix, so a real
// gap is pre-existing fragmentation or external damage — the startup R53
// repair owns that class, not this pass.

import (
	"fmt"
)

// startDeepIntegrityCheck launches the one-shot whole-chain parent-linkage
// verification in the background. Called at the tail of Node.Start, after
// every component is up, so a slow pass never delays boot.
func (n *Node) startDeepIntegrityCheck() {
	if n == nil || n.blockStore == nil {
		return
	}
	go func() {
		tip, damagedAt, gapAt, err := n.blockStore.VerifyFullContinuity()
		if err != nil {
			// A db-level scan failure is transient (the next restart
			// re-runs the pass). Never fail closed on a scanner error —
			// that would make a cold page cache look like corruption.
			nodeLog.Warn("R33 deep-integrity pass skipped (scan error): %v", err)
			return
		}
		if gapAt != 0 {
			nodeLog.Warn("R33 deep-integrity pass: number-index gap at height %d "+
				"(verified continuous through %d) — pre-existing fragmentation or "+
				"external damage; the startup R53 repair owns this class. Pass stopped.",
				gapAt, tip)
			return
		}
		if damagedAt != 0 {
			n.markStateTrustBroken(fmt.Sprintf(
				"R33 deep-integrity pass: block %d failed continuity verification "+
					"(missing, undecodable, or parent-linkage mismatch against block %d)",
				damagedAt, damagedAt-1))
			return
		}
		nodeLog.Info("R33 deep-integrity pass: full chain verified continuous through height %d", tip)
	}()
}

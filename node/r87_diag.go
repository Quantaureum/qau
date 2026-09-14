// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"os"
	"sync/atomic"

	"github.com/quantaureum/qau/types"
)

// R87-STATEROOT-DIAG: opt-in probes for the long-standing "state root mismatch"
// WARN (tracked as M4, worked around by R63-STATE-ROOT-TRUST).
//
// Five hypotheses were falsified at unit level before adding these probes, each
// left behind as a regression test:
//   - proposer-builds-on-Copy() asymmetry  (node/r87_stateroot_copy_test.go)
//   - Go map iteration order in Commit     (node/r87_order_test.go)
//   - double CommitWithBlock(h) in buildBlock (node/r87_double_commit_test.go)
//   - prune/snapshot side effects past pruneKeepBlocks (node/r87_empty_commit_test.go)
//   - incomplete fork rollback             (qaudb/state/r87_rollback_test.go)
//
// Live devnet observation that narrowed it further: a freshly reset chain shows
// ZERO mismatches across 38 blocks (including tx-carrying ones), while a chain
// that had accepted 32 forks mismatched on essentially every block. The trigger
// is therefore in the fork-recovery path, not in ordinary block application.
//
// These probes print the root on both sides of every commit so one devnet run
// that does fork shows exactly which side moves. Enabled with QAU_R87_DIAG=1;
// off by default at the cost of a single atomic load.
var r87DiagEnabled atomic.Bool

func init() {
	if os.Getenv("QAU_R87_DIAG") == "1" {
		r87DiagEnabled.Store(true)
	}
}

// r87Diag reports whether R87 state-root diagnostics are enabled.
func r87Diag() bool {
	return r87DiagEnabled.Load()
}

// r87Short renders the first 8 bytes of a hash for compact log lines.
func r87Short(h types.Hash) string {
	return hex.EncodeToString(h[:8])
}

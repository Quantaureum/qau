// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"log"
	"os"
	"sync/atomic"

	"github.com/quantaureum/qau/types"
)

// R88-PROPONENT-DIAG: opt-in probe for the R88 fork class (restarted vs
// never-restarted nodes electing different proposers for the same slot).
//
// The R88 fork class is caused when a restarted node's epoch-2 VRF
// accumulator differs from its peers' (different shuffle seed →
// different warm-shuffle proposer), and the producer's modulo round-robin
// fallback then proposed on a schedule that no validator verifies (fixed
// by R88-A; the accumulator asymmetry itself is tracked as R88-C).
//
// This probe logs the shuffle seed inputs the FIRST time each epoch's
// shuffle is computed (cache-miss path of GetProposerForSlot). A diagnostic
// run with QAU_R88_DIAG=1 shows, per epoch:
//
//	R88DIAG shuffle-seed epoch=529 n=3 srcEpoch=527 accPresent=true acc=1122334455667788
//
// Diffing the acc= values across nodes for the disputed epoch pinpoints
// exactly WHICH node's accumulator diverged and at which epoch — the data
// needed to close R88-C (replay-vs-live accumulator asymmetry).
//
// Enabled with QAU_R88_DIAG=1; off by default at the cost of a single
// atomic load.
var r88DiagEnabled atomic.Bool

func init() {
	if os.Getenv("QAU_R88_DIAG") == "1" {
		r88DiagEnabled.Store(true)
	}
}

// r88Diag reports whether R88 proposer-election diagnostics are enabled.
func r88Diag() bool {
	return r88DiagEnabled.Load()
}

// r88LogShuffleSeed emits the seed inputs for an epoch's first shuffle
// computation. accFirst8 carries the first 8 bytes of the epoch-2 VRF
// accumulator (enough to diff across nodes without flooding the log).
func r88LogShuffleSeed(epoch uint64, n int, accPresent bool, acc types.Hash) {
	if !r88Diag() || epoch < 2 {
		// epoch < 2 always uses the genesis root (not the accumulator) —
		// nothing to diff there.
		return
	}
	acc8 := types.Hash{}
	copy(acc8[:8], acc[:8])
	log.Printf("[R88DIAG] shuffle-seed epoch=%d n=%d srcEpoch=%d accPresent=%v acc=%x (coldStart fallback in use if accPresent=false)",
		epoch, n, epochSrcEpoch(epoch), accPresent, acc8[:8])
}

// epochSrcEpoch returns the accumulator source epoch for a shuffle epoch
// (epoch-2, CONS-R13-M03), clamped for display purposes only.
func epochSrcEpoch(epoch uint64) uint64 {
	if epoch < 2 {
		return 0
	}
	return epoch - 2
}

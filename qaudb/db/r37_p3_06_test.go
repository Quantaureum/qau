// Quantaureum Node source, version 1.0.0.
package db

import "testing"

// TestR37_P3_06_MaxBatchOps_CoversFullBlockWorstCase guards the alignment
// between MaxBatchOps and the encoding package's per-block transaction cap
// (maxTxPerBlock = 10000, unexported in encoding/block.go). If governance
// ever raises the gas limit / tx cap, MaxBatchOps must be raised in tandem
// or PutBlock / deleteBlockAtHeightLocked batches start hitting
// ErrBatchFull on a full block.
func TestR37_P3_06_MaxBatchOps_CoversFullBlockWorstCase(t *testing.T) {
	const maxTxPerBlock = 10000 // mirrors encoding.maxTxPerBlock (unexported)

	// PutBlock same-height overwrite, worst case:
	//   3 block records (block data + header data + number mapping)
	//   2 * maxTxPerBlock old tx-location + receipt deletes
	//   1 * maxTxPerBlock new tx locations
	//   1 latestBlockKey update
	putWorstCase := 3 + 3*maxTxPerBlock + 1
	if MaxBatchOps < putWorstCase {
		t.Fatalf("MaxBatchOps=%d cannot fit a full-block overwrite batch (%d ops)",
			MaxBatchOps, putWorstCase)
	}

	// deleteBlockAtHeightLocked, worst case:
	//   3 block record deletes
	//   2 * maxTxPerBlock tx-location + receipt deletes
	//   1 latestBlockKey update
	deleteWorstCase := 3 + 2*maxTxPerBlock + 1
	if MaxBatchOps < deleteWorstCase {
		t.Fatalf("MaxBatchOps=%d cannot fit a full-block delete batch (%d ops)",
			MaxBatchOps, deleteWorstCase)
	}
}

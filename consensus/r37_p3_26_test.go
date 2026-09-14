// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// TestR37_P3_26_GroupKeyHistoryRetention verifies the R37-P3-26 fix:
// QTDFinalityState.groupKeyHistory no longer grows without bound. When a
// new DKG group key is recorded (the only writer), entries older than
// qtdGroupKeyHistoryRetainEpochs relative to the activation epoch are
// pruned, while keys inside the retention window remain available for
// historical seal verification.
//
// R39-P1-01 (2026-08-02): upgraded the stub keys from short ASCII strings
// to real 1952-byte (crypto.Dilithium3PublicKeySize) keys, because the
// R39-P1-01 write-side gate now strictly enforces the canonical length.
// Each epoch's key is parameterized by `e` so the round-trip check below
// stays meaningful. The test still pins the R37-P3-26 pruning SEMANTICS
// (window boundary, oldest epoch retention, underflow guard).
func TestR37_P3_26_GroupKeyHistoryRetention(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	// Simulate DKG rotations across more epochs than the retention window.
	const lastEpoch = uint64(2*qtdGroupKeyHistoryRetainEpochs + 100)
	for e := uint64(0); e <= lastEpoch; e++ {
		// Each epoch gets a distinct 1952-byte non-zero key derived from e.
		key := testDilithium3GroupKey(byte(e % 250))
		if len(key) != crypto.Dilithium3PublicKeySize {
			t.Fatalf("test key len = %d, want %d", len(key), crypto.Dilithium3PublicKeySize)
		}
		qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: key}, e)
	}

	qfs.mu.RLock()
	size := len(qfs.groupKeyHistory)
	qfs.mu.RUnlock()
	if size > qtdGroupKeyHistoryRetainEpochs {
		t.Fatalf("groupKeyHistory size = %d, exceeds retention window %d (unbounded growth)",
			size, qtdGroupKeyHistoryRetainEpochs)
	}

	// The oldest retained epoch must be lastEpoch - retain + 1.
	oldestRetained := lastEpoch - qtdGroupKeyHistoryRetainEpochs + 1

	// Epochs older than the window must have been pruned.
	for _, e := range []uint64{0, 1, oldestRetained - 1} {
		qfs.mu.RLock()
		_, ok := qfs.groupKeyHistory[e]
		qfs.mu.RUnlock()
		if ok {
			t.Errorf("groupKeyHistory[%d] should have been pruned (outside retention window)", e)
		}
	}

	// Epochs inside the window must retain their historical keys.
	for _, e := range []uint64{oldestRetained, lastEpoch - 1, lastEpoch} {
		qfs.mu.RLock()
		got, ok := qfs.groupKeyHistory[e]
		qfs.mu.RUnlock()
		if !ok {
			t.Fatalf("groupKeyHistory[%d] was pruned but is inside the retention window", e)
		}
		want := testDilithium3GroupKey(byte(e % 250))
		if string(got) != string(want) {
			t.Errorf("groupKeyHistory[%d] round-trip mismatch (R39-P1-01 fixture)", e)
		}
	}

	// Recording a key at an epoch below the retention window must not
	// prune anything (uint64 underflow guard).
	qfs2 := NewQTDFinalityState(qpos)
	for e := uint64(0); e < 10; e++ {
		qfs2.SetQTDSignerForEpoch(&epochKeySigner{groupKey: testDilithium3GroupKey(byte(e + 1))}, e)
	}
	qfs2.mu.RLock()
	size2 := len(qfs2.groupKeyHistory)
	qfs2.mu.RUnlock()
	if size2 != 10 {
		t.Errorf("groupKeyHistory size = %d after 10 low-epoch rotations, want 10 (no pruning below window)", size2)
	}
}

// Quantaureum Node source, version 1.0.0.
package rpc

// R24 (2026-10-29) — auditor findings X07 / X09 / X11 on the public finality
// RPCs:
//
//   - X07: qau_stardust_getFinality read the seal record and the seal status
//     in TWO separate consensus reads; a concurrent completion could produce
//     a body whose record and status described different moments. Both RPCs
//     now use the single-snapshot GetSlotSealDetails.
//   - X09: consensusSealFinalized skipped the epoch cross-check at epoch 0 —
//     the published field now uses the strict IsSealConsensusFinalized, whose
//     cross-check is performed for every epoch.
//   - X11: sealedAt had two JSON encodings (a Unix-seconds number in
//     getFinality, an RFC3339 string in getSealStatus). Both RPCs now emit
//     Unix seconds.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestR24_GetFinality_SealedAtIsUnixSecondsEverywhere pins the single sealedAt
// encoding (X11): an integer number of seconds since the Unix epoch in BOTH
// finality RPCs, and the same value for the same record.
func TestR24_GetFinality_SealedAtIsUnixSecondsEverywhere(t *testing.T) {
	qpos := r23NewQPOS(t)
	api := NewStardustAPI(qpos)
	const slot = uint64(33) // epoch 1
	blockHash := r23Hash(0xd0)

	r23AnnounceSeal(t, qpos, slot, blockHash)

	finality := r23FinalityResult(t, api, slot)
	status := r23SealStatusResult(t, api, slot)

	getGot, ok := finality["sealedAt"]
	if !ok {
		t.Fatalf("getFinality is missing sealedAt: %v", finality)
	}
	statusGot, ok := status["sealedAt"]
	if !ok {
		t.Fatalf("getSealStatus is missing sealedAt: %v", status)
	}
	want := time.Unix(int64(slot), 0).Unix()
	if got, ok := getGot.(int64); !ok || got != want {
		t.Fatalf("getFinality sealedAt = %v (%T), want int64 %d", getGot, getGot, want)
	}
	if got, ok := statusGot.(int64); !ok || got != want {
		t.Fatalf("getSealStatus sealedAt = %v (%T), want int64 %d", statusGot, statusGot, want)
	}

	// The JSON encoding is a number in both bodies — assert through a real
	// marshal, which is what an RPC client sees.
	for name, body := range map[string]map[string]any{"getFinality": finality, "getSealStatus": status} {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s body: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal %s body: %v", name, err)
		}
		if _, ok := decoded["sealedAt"].(float64); !ok {
			t.Fatalf("%s sealedAt does not JSON-encode as a number: %v", name, decoded["sealedAt"])
		}
	}
}

// TestR24_GetFinality_StatusAndRecordDescribeSameRecord pins the single
// snapshot rule (X07): the status facts and the record payload in one body
// always describe the SAME retained agreement.
func TestR24_GetFinality_StatusAndRecordDescribeSameRecord(t *testing.T) {
	qpos := r23NewQPOS(t)
	api := NewStardustAPI(qpos)
	const slot = uint64(33)
	sideBranch := r23Hash(0xb0)
	canonical := r23Hash(0xc0)

	r23AnnounceSeal(t, qpos, slot, sideBranch)
	qpos.SetSlotBlockRoot(slot, canonical)

	for name, body := range map[string]map[string]any{
		"getFinality":   r23FinalityResult(t, api, slot),
		"getSealStatus": r23SealStatusResult(t, api, slot),
	} {
		// sealRecorded=true and canonicalState=differs must describe the SAME
		// record whose blockHash the body carries.
		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertString(t, body, "canonicalState", "differs")
		r23AssertString(t, body, "blockHash", "0x"+hexHash(sideBranch))
		if name == "getFinality" {
			r23AssertBool(t, body, "isFinalized", false)
		} else {
			r23AssertBool(t, body, "finalized", false)
		}
	}
}

// TestR24_GetFinality_ConsensusSealFinalizedIsStrict pins the strict epoch
// cross-check behind the published field (X09).
func TestR24_GetFinality_ConsensusSealFinalizedIsStrict(t *testing.T) {
	t.Run("epoch 0 without a named root", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(5) // epoch 0 — the case the R24 revision skipped

		r23AnnounceSeal(t, qpos, slot, types.Hash{0x50})

		body := r23FinalityResult(t, api, slot)
		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertBool(t, body, "consensusSealFinalized", false)
	})

	t.Run("marker behind", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(64) // epoch 2, marker still at epoch 0

		r23AnnounceSeal(t, qpos, slot, types.Hash{0x64})

		body := r23FinalityResult(t, api, slot)
		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertBool(t, body, "consensusSealFinalized", false)
	})

	t.Run("marker caught up", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(32) // epoch 1
		canonical := r23Hash(0xa0)

		qpos.SetSlotBlockRoot(slot, canonical)
		r23AnnounceSeal(t, qpos, slot, canonical)
		r23WaitFor(t, "the QPOS epoch marker to reach epoch 1", 5*time.Second, func() bool {
			return qpos.GetFinalizedEpoch() >= 1
		})

		body := r23FinalityResult(t, api, slot)
		r23AssertBool(t, body, "consensusSealFinalized", true)
	})
}

// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// ── R23 (2026-10-29): the public QTD finality surface must report the
// independent facts, never a single collapsed "finalized" boolean.
//
// Three states are pinned here:
//
//  1. no seal recorded at all;
//  2. a seal whose block IS the slot's canonical root (the normal case);
//  3. a RETAINED seal whose block provably is NOT the canonical root —
//     a quorum agreement over a side-branch block.
//
// State 3 is the one that used to be reported as finalized: IsSlotFinalized
// cannot tell a canonical seal from a seal over a fork block, so the RPCs
// answered "finalized: true" for a fork block and handed out that fork
// block's hash at the same time.

// r23MockSigner is a consensus.ThresholdKeySigner stub used to create real
// QTD seal records from outside the consensus package.
//
// The rpc package cannot reach the consensus package's internals, so the
// record must be created through an exported API. ReceiveSealAnnouncement is
// the only exported path that accepts a seal without a Review Chamber
// approval — and it is not a shortcut: it verifies the canonical root (when
// known), the sealer membership, the 2/3 stake bar, the group key and the
// signature itself.
type r23MockSigner struct{}

func (r23MockSigner) SignBlock(int, []byte) ([]byte, error) {
	return nil, errors.New("r23: unsupported")
}
func (r23MockSigner) SignVote(int, []byte) ([]byte, error) {
	return nil, errors.New("r23: unsupported")
}

// VerifyBlock accepts the announcement's signature: the record this fixture
// creates is a threshold-agreement PROOF, and the property under test is how
// the RPC reports that proof — not whether the stub signature is valid.
func (r23MockSigner) VerifyBlock([]byte, []byte, []byte) bool { return true }
func (r23MockSigner) VerifyVote([]byte, []byte, []byte) bool  { return true }

// GroupPublicKey returns a non-degenerate key. It is deliberately NOT
// Dilithium3-sized: the write-side gate keeps only exact-size keys in the
// group key history, so the lookup falls back to the live signer — which is
// the path a single-DKG-group deployment uses.
func (r23MockSigner) GroupPublicKey() []byte { return []byte("r23-mock-group-public-key") }
func (r23MockSigner) IsThresholdMode() bool  { return true }
func (r23MockSigner) Threshold() int         { return 0 }
func (r23MockSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, errors.New("r23: unsupported")
}

// r23NewQPOS builds a three-validator QPOS with the Three Chambers and a
// threshold signer wired up — enough for a real seal record to be created
// and for the QPOS finality markers to move.
func r23NewQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()

	validators := make([]*consensus.Validator, 0, 3)
	for i := 1; i <= 3; i++ {
		validators = append(validators, &consensus.Validator{
			Address: types.BytesToAddress([]byte{byte(i)}),
			Stake:   big.NewInt(1000),
			Active:  true,
		})
	}
	vs, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("GetQTDFinality returned nil after InitChambers")
	}
	qfs.SetQTDSigner(r23MockSigner{})
	return qpos
}

// r23AnnounceSeal creates a real QTD seal record for the slot.
func r23AnnounceSeal(t *testing.T, qpos *consensus.QPOS, slot uint64, blockHash types.Hash) {
	t.Helper()
	qfs := qpos.GetQTDFinality()
	// Sealers 0 and 1 hold 2/3 of the total stake — exactly the QTD quorum bar.
	if !qfs.ReceiveSealAnnouncement(slot, blockHash, []byte("r23-threshold-signature-bytes"), []int{0, 1}) {
		t.Fatalf("ReceiveSealAnnouncement(slot=%d, hash=%s) was rejected", slot, blockHash.String())
	}
}

// r23WaitFor polls a condition until it holds or the timeout expires.
func r23WaitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// r23Hash builds a distinct, non-zero 32-byte hash.
func r23Hash(seed byte) types.Hash {
	h := types.Hash{}
	for i := range h {
		h[i] = seed + byte(i)
	}
	return h
}

// hexHash returns the hex encoding of a hash, without the 0x prefix.
func hexHash(h types.Hash) string {
	return hex.EncodeToString(h[:])
}

// r23FinalityResult calls qau_stardust_getFinality and returns the body.
func r23FinalityResult(t *testing.T, api *StardustAPI, slot uint64) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"slot": slot})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	res, rerr := api.GetFinality(context.Background(), params)
	if rerr != nil {
		t.Fatalf("GetFinality(slot=%d): %v", slot, rerr)
	}
	body, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("GetFinality returned %T, want map[string]any", res)
	}
	return body
}

// r23SealStatusResult calls qau_tss_getSealStatus and returns the body.
func r23SealStatusResult(t *testing.T, api *StardustAPI, slot uint64) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"slot": slot})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	res, rerr := api.GetSealStatus(context.Background(), params)
	if rerr != nil {
		t.Fatalf("GetSealStatus(slot=%d): %v", slot, rerr)
	}
	body, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("GetSealStatus returned %T, want map[string]any", res)
	}
	return body
}

// r23AssertBool asserts a boolean field of an RPC body.
func r23AssertBool(t *testing.T, body map[string]any, key string, want bool) {
	t.Helper()
	got, ok := body[key]
	if !ok {
		t.Fatalf("response is missing the %q field: %v", key, body)
	}
	value, ok := got.(bool)
	if !ok {
		t.Fatalf("field %q is %T, want bool", key, got)
	}
	if value != want {
		t.Fatalf("field %q = %v, want %v (full body: %v)", key, value, want, body)
	}
}

// r23AssertString asserts a string field of an RPC body.
func r23AssertString(t *testing.T, body map[string]any, key, want string) {
	t.Helper()
	got, ok := body[key]
	if !ok {
		t.Fatalf("response is missing the %q field: %v", key, body)
	}
	value, ok := got.(string)
	if !ok {
		t.Fatalf("field %q is %T, want string", key, got)
	}
	if value != want {
		t.Fatalf("field %q = %q, want %q (full body: %v)", key, value, want, body)
	}
}

// TestR23_GetFinality_ReportsThreeIndependentFacts pins the honest
// qau_stardust_getFinality body in all three states.
func TestR23_GetFinality_ReportsThreeIndependentFacts(t *testing.T) {
	t.Run("no seal recorded", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)

		body := r23FinalityResult(t, api, 32)

		r23AssertBool(t, body, "isFinalized", false)
		r23AssertBool(t, body, "sealRecorded", false)
		r23AssertBool(t, body, "canonical", false)
		r23AssertString(t, body, "canonicalState", "unknown")
		r23AssertBool(t, body, "epochFinalized", false)
		r23AssertBool(t, body, "consensusSealFinalized", false)
		if _, ok := body["blockHash"]; ok {
			t.Fatalf("a slot without a seal record must not report a blockHash: %v", body)
		}
	})

	t.Run("canonical seal", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(32) // epoch 1 — epoch 0 markers are ambiguous
		canonical := r23Hash(0xa0)

		qpos.SetSlotBlockRoot(slot, canonical)
		r23AnnounceSeal(t, qpos, slot, canonical)
		// The QPOS finality markers move asynchronously (the seal completion
		// hands the finalization off to a goroutine).
		r23WaitFor(t, "the QPOS epoch marker to reach epoch 1", 5*time.Second, func() bool {
			return qpos.GetFinalizedEpoch() >= 1
		})

		body := r23FinalityResult(t, api, slot)

		r23AssertBool(t, body, "isFinalized", true)
		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertBool(t, body, "canonical", true)
		r23AssertString(t, body, "canonicalState", "matches")
		r23AssertBool(t, body, "epochFinalized", true)
		r23AssertBool(t, body, "consensusSealFinalized", true)
		r23AssertString(t, body, "blockHash", "0x"+hexHash(canonical))
	})

	t.Run("retained side-branch seal", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(33) // epoch 1
		sideBranch := r23Hash(0xb0)
		canonical := r23Hash(0xc0)

		// The agreement is recorded BEFORE the canonical root of the slot is
		// known, so the seal cannot be rejected as non-canonical at the time.
		r23AnnounceSeal(t, qpos, slot, sideBranch)
		// The canonical block of the slot lands and DIFFERS from the sealed
		// block: the agreement provably attests a side-branch block.
		qpos.SetSlotBlockRoot(slot, canonical)

		body := r23FinalityResult(t, api, slot)

		// The agreement is still recorded — it is the threshold-agreement
		// proof and must survive (R4-CORE-04).
		r23AssertBool(t, body, "sealRecorded", true)
		// …but it is provably NOT the canonical block, so it is not final.
		r23AssertBool(t, body, "canonical", false)
		r23AssertString(t, body, "canonicalState", "differs")
		r23AssertBool(t, body, "isFinalized", false)
		r23AssertBool(t, body, "epochFinalized", false)
		// R24 (2026-10-29): consensusSealFinalized is the STRICT consensus
		// view (IsSealConsensusFinalized): a seal agreement is recorded AND
		// the QPOS epoch marker has caught up to the slot's epoch. A
		// side-branch seal never advances the marker, so while the marker is
		// still behind it reports false — the map-only "a record exists, so
		// true" answer the R23 revision pinned is gone.
		r23AssertBool(t, body, "consensusSealFinalized", false)
		// The reported hash is the sealed (side-branch) block — the client can
		// see exactly WHICH block the agreement covers.
		r23AssertString(t, body, "blockHash", "0x"+hexHash(sideBranch))
	})
}

// TestR23_GetSealStatus_ReportsThreeIndependentFacts pins the honest
// qau_tss_getSealStatus body in all three states.
func TestR23_GetSealStatus_ReportsThreeIndependentFacts(t *testing.T) {
	t.Run("no seal recorded", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)

		body := r23SealStatusResult(t, api, 32)

		r23AssertBool(t, body, "finalized", false)
		r23AssertBool(t, body, "sealRecorded", false)
		r23AssertBool(t, body, "canonical", false)
		r23AssertString(t, body, "canonicalState", "unknown")
		r23AssertBool(t, body, "epochFinalized", false)
		r23AssertBool(t, body, "consensusSealFinalized", false)
		if _, ok := body["blockHash"]; ok {
			t.Fatalf("a slot without a seal record must not report a blockHash: %v", body)
		}
		if _, ok := body["pending"]; ok {
			t.Fatalf("a slot without a pending seal must not report pending: %v", body)
		}
	})

	t.Run("canonical seal", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(32)
		canonical := r23Hash(0xa0)

		qpos.SetSlotBlockRoot(slot, canonical)
		r23AnnounceSeal(t, qpos, slot, canonical)
		r23WaitFor(t, "the QPOS epoch marker to reach epoch 1", 5*time.Second, func() bool {
			return qpos.GetFinalizedEpoch() >= 1
		})

		body := r23SealStatusResult(t, api, slot)

		r23AssertBool(t, body, "finalized", true)
		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertBool(t, body, "canonical", true)
		r23AssertString(t, body, "canonicalState", "matches")
		r23AssertBool(t, body, "epochFinalized", true)
		r23AssertBool(t, body, "consensusSealFinalized", true)
		r23AssertString(t, body, "blockHash", "0x"+hexHash(canonical))
		if _, ok := body["pending"]; ok {
			t.Fatalf("a completed seal must not report a pending seal: %v", body)
		}
	})

	t.Run("retained side-branch seal", func(t *testing.T) {
		qpos := r23NewQPOS(t)
		api := NewStardustAPI(qpos)
		const slot = uint64(33)
		sideBranch := r23Hash(0xb0)
		canonical := r23Hash(0xc0)

		r23AnnounceSeal(t, qpos, slot, sideBranch)
		qpos.SetSlotBlockRoot(slot, canonical)

		body := r23SealStatusResult(t, api, slot)

		r23AssertBool(t, body, "sealRecorded", true)
		r23AssertBool(t, body, "canonical", false)
		r23AssertString(t, body, "canonicalState", "differs")
		r23AssertBool(t, body, "finalized", false)
		r23AssertBool(t, body, "epochFinalized", false)
		// R24: the strict consensus view — the marker is still behind (the
		// side-branch seal never advanced it), so this is false.
		r23AssertBool(t, body, "consensusSealFinalized", false)
		r23AssertString(t, body, "blockHash", "0x"+hexHash(sideBranch))
	})
}

// TestR23_GetSealStatus_RecordAndPendingAreDisambiguated pins the R23-02
// schema rule: when a retained agreement and a re-seal coexist, the legacy
// key names stay bound to the RECORD and the pending seal gets its own keys.
//
// The state is unreachable from outside the consensus package (a pending seal
// can only be created by RequestSeal, which needs a Review Chamber approval),
// so the response mapping is exercised directly.
func TestR23_GetSealStatus_RecordAndPendingAreDisambiguated(t *testing.T) {
	recordHash := r23Hash(0xb0)
	pendingHash := r23Hash(0xc0)

	record := &consensus.InstantFinalityRecord{
		Slot:      33,
		BlockHash: recordHash,
		Sealers:   []int{0, 1, 2},
		SealedAt:  time.Unix(33, 0),
	}
	pending := &consensus.PendingSeal{
		Slot:          33,
		BlockHash:     pendingHash,
		PartialSigs:   map[int][]byte{0: []byte("partial-signature-0"), 1: []byte("partial-signature-1")},
		RequiredCount: 2,
	}
	status := consensus.SlotSealStatus{
		SealRecorded: true,
		RootState:    consensus.SealRootDiffers,
		EpochFinal:   false,
	}

	result := sealStatusResult(33, status, record, pending, true)

	// The legacy keys describe the RECORD.
	r23AssertString(t, result, "blockHash", "0x"+hexHash(recordHash))
	if got, ok := result["sealerCount"].(int); !ok || got != 3 {
		t.Fatalf("sealerCount = %v, want 3 (the record's sealers)", result["sealerCount"])
	}
	// The pending seal has its own keys.
	r23AssertString(t, result, "pendingBlockHash", "0x"+hexHash(pendingHash))
	if got, ok := result["pendingSealerCount"].(int); !ok || got != 2 {
		t.Fatalf("pendingSealerCount = %v, want 2 (the pending partial signatures)", result["pendingSealerCount"])
	}
	r23AssertBool(t, result, "pending", true)
	r23AssertBool(t, result, "completed", false)
	r23AssertBool(t, result, "finalized", false)
	r23AssertBool(t, result, "sealRecorded", true)
	r23AssertString(t, result, "canonicalState", "differs")
}

// TestR23_GetSealStatus_PendingOnlyUsesLegacyKeys pins the other half of
// the R23-02 rule: without a record, the legacy keys describe the pending
// seal — the behavior clients relied on before a record existed.
func TestR23_GetSealStatus_PendingOnlyUsesLegacyKeys(t *testing.T) {
	pendingHash := r23Hash(0xc0)
	pending := &consensus.PendingSeal{
		Slot:          34,
		BlockHash:     pendingHash,
		PartialSigs:   map[int][]byte{0: []byte("partial-signature-0")},
		RequiredCount: 2,
	}

	result := sealStatusResult(34, consensus.SlotSealStatus{}, nil, pending, false)

	r23AssertString(t, result, "blockHash", "0x"+hexHash(pendingHash))
	if got, ok := result["sealerCount"].(int); !ok || got != 1 {
		t.Fatalf("sealerCount = %v, want 1 (the pending partial signatures)", result["sealerCount"])
	}
	if _, ok := result["pendingBlockHash"]; ok {
		t.Fatalf("without a record the pending seal must use the legacy keys only: %v", result)
	}
	r23AssertBool(t, result, "finalized", false)
	r23AssertBool(t, result, "sealRecorded", false)
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/types"
)

// approveSlotForQTD pre-approves the slot in the Review Chamber so that
// RequestQTDFinalitySeal can succeed. This mirrors the test setup in
// qtd_finality_test.go (TestQTDFinalityRequestSeal).
func approveSlotForQTD(t *testing.T, qpos *QPOS, slot uint64) {
	t.Helper()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}
	review := coordinator.GetReviewChamber()
	if review == nil {
		t.Fatal("review chamber is nil")
	}
	review.mu.Lock()
	review.slotResults[slot] = &ReviewSlotResult{
		Slot:          slot,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()
}

// TestQTD_H02_SubmitCompletedSeal_NoLockFreeSignerRead verifies that
// SubmitCompletedSeal reads qtdSigner atomically under qfs.mu.RLock
// (not lock-free). The QTD-H02 fix addresses a Go data race + TOCTOU:
// without the lock, a concurrent SetQTDSigner could tear the interface
// value (panic) or swap in a malicious signer between the nil-check and
// VerifyBlock (security bypass).
//
// This test runs SubmitCompletedSeal concurrently with SetQTDSigner
// under the Go race detector to confirm no race is reported. Run with:
//
//	go test -race -run TestQTD_H02_SubmitCompletedSeal_NoLockFreeSignerRead
func TestQTD_H02_SubmitCompletedSeal_NoLockFreeSignerRead(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil after InitChambers")
	}
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	// Create a pending seal so SubmitCompletedSeal has something to operate on.
	slot := uint64(100)
	blockHash := types.Hash{0x42}
	qpos.SetSlotBlockRoot(slot, blockHash)
	approveSlotForQTD(t, qpos, slot)
	if err := qpos.RequestQTDFinalitySeal(slot, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	// Concurrently: goroutine A toggles SetQTDSigner(nil) / SetQTDSigner(mock)
	// while goroutine B calls SubmitCompletedSeal. Under the race detector,
	// a lock-free read of qtdSigner in SubmitCompletedSeal would be flagged.
	// QTD-H02 fix ensures both entry points snapshot qtdSigner under qfs.mu.
	var wg sync.WaitGroup
	const iterations = 50

	// Goroutine A: rapidly toggle signer (bounded iterations).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			qfs.SetQTDSigner(&mockThresholdSigner{})
			qfs.SetQTDSigner(nil)
		}
	}()

	// Goroutine B: repeatedly call SubmitCompletedSeal with a dummy signature.
	// We expect it to return an error (signer missing or signature invalid),
	// but it must NOT race / panic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Use a dummy signature — SubmitCompletedSeal will fail with
			// "signature verification failed" or "qtdSigner not configured",
			// both of which are acceptable. The point is to exercise the
			// signer read path under concurrency.
			_ = qfs.SubmitCompletedSeal(slot, []byte("dummy-signature"), []int{0, 1, 2})
		}
	}()

	wg.Wait()
}

// TestQTD_H02_AggregateAndCompleteSeal_NoLockFreeSignerRead verifies the
// same invariant on the AggregateAndCompleteSeal entry point. The QTD-H02
// fix must be applied to ALL public entry points that read qtdSigner, not
// just SubmitCompletedSeal — otherwise a concurrent SetQTDSigner can tear
// the interface value or swap in a malicious signer between the nil-check
// and AggregatePartialSignatures.
//
// Run with: go test -race -run TestQTD_H02_AggregateAndCompleteSeal_NoLockFreeSignerRead
func TestQTD_H02_AggregateAndCompleteSeal_NoLockFreeSignerRead(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil after InitChambers")
	}
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	// Create several pending seals so each call has something to operate on.
	for slot := uint64(200); slot < 220; slot++ {
		blockHash := types.Hash{byte(slot)}
		qpos.SetSlotBlockRoot(slot, blockHash)
		approveSlotForQTD(t, qpos, slot)
		if err := qpos.RequestQTDFinalitySeal(slot, blockHash); err != nil {
			t.Fatalf("RequestQTDFinalitySeal failed for slot %d: %v", slot, err)
		}
	}

	var wg sync.WaitGroup
	const iterations = 50

	// Goroutine A: toggle signer (bounded iterations).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			qfs.SetQTDSigner(&mockThresholdSigner{})
			qfs.SetQTDSigner(nil)
		}
	}()

	// Goroutine B: call AggregateAndCompleteSeal on each slot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			for slot := uint64(200); slot < 220; slot++ {
				_ = qfs.AggregateAndCompleteSeal(slot, []int{0, 1, 2})
			}
		}
	}()

	wg.Wait()
}

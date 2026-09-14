// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ExecuteFullFlow is a TEST-ONLY convenience method that runs the entire
// three-chambers finality flow synchronously for a single slot.
//
// P0-5 FIX (2026-07-13): This method was moved from three_provinces.go to a
// _test.go file because it submits placeholder ("mock") partial seal
// signatures instead of real TSS signatures. In production, partial seals are
// delivered asynchronously via P2P from executive chamber members, not
// fabricated inline. Keeping placeholder signing in production code created a
// false impression that ExecuteFullFlow is production-safe — it is NOT.
//
// DoD: `grep -r "partial-seal-%d-min16bytes" consensus/` matches only in *_test.go.
//
// This method is used by integration tests (e.g. TestStardustV2_Integration_FullFlow_ExecuteFullFlow)
// to validate the lifecycle state machine without requiring a real TSS signer.
func (tpf *ThreeChambersFlow) ExecuteFullFlow(slot uint64, blockHash types.Hash, proposerIndex int) error {
	// CHAMBER-H03 + QUANTUM-FIX (R31, 2026-07-27): Two security fixes
	// broke test helpers that were written before the fixes existed:
	//
	// 1. CHAMBER-H03: CanSeal now fail-closes when no executive assignment
	//    exists for the slot's epoch. Previously CanSeal returned true if the
	//    validator was merely "in the executive chamber" (IsInChamber), which
	//    allowed sealing for ANY epoch. Now it requires explicit
	//    epochExecutive[epoch] membership.
	//
	// 2. QUANTUM- completeSealLockedFinalize now fail-closes when
	//    GetSlotBlockRoot(slot) returns false (no canonical root known).
	//    Previously it logged a warning and accepted the seal.
	//
	// Both fixes are correct for production security but break test helpers
	// that use arbitrary slot numbers (e.g. slot 10000, epoch 312) without
	// setting up executive assignments or canonical roots. This helper now
	// sets up both BEFORE attempting the seal, so tests can use any slot
	// number without manually configuring epoch-specific state.
	epoch := SlotToEpoch(slot)
	coordinator := tpf.qpos.GetChambersCoordinator()
	if coordinator != nil {
		// Assign executive for this epoch if not already assigned.
		if !coordinator.HasExecutiveAssignment(epoch) {
			_ = coordinator.AssignExecutive([]int{4, 5, 6}, epoch)
			executive := coordinator.GetExecutiveChamber()
			if executive != nil {
				_ = executive.SetMembers([]int{4, 5, 6}, epoch)
				_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
			}
		}
	}
	// Pre-populate canonical root so QUANTUM- fail-closed gate passes.
	tpf.qpos.SetSlotBlockRoot(slot, blockHash)

	if err := tpf.ProposeBlock(slot, blockHash, proposerIndex); err != nil {
		return fmt.Errorf("propose failed: %w", err)
	}

	if err := tpf.ReviewBlock(slot); err != nil {
		return fmt.Errorf("review failed: %w", err)
	}

	lifecycle := tpf.GetLifecycle(slot)
	if lifecycle != nil && lifecycle.Phase == PhaseRejected {
		return fmt.Errorf("block rejected by review chamber for slot %d", slot)
	}

	if err := tpf.SealBlock(slot); err != nil {
		return fmt.Errorf("seal failed: %w", err)
	}

	// Submit mock partial seals from each executive member (simulating P2P
	// delivery). Each partial seal is >= 16 bytes to pass MinPartialSealSize.
	// NOTE: These are NOT real signatures — they provide no cryptographic
	// guarantees and are sufficient only for consensus state-machine testing.
	qfs := tpf.qpos.GetQTDFinality()
	if qfs != nil {
		if coordinator != nil {
			executive := coordinator.GetExecutiveChamber()
			if executive != nil {
				members := executive.Members()
				for _, member := range members {
					partialSig := []byte(fmt.Sprintf("partial-seal-%d-min16bytes", member))
					if err := qfs.SubmitPartialSeal(member, slot, partialSig); err != nil {
						tpfLog.Warnf("Failed to submit partial seal for member %d at slot %d: %v", member, slot, err)
					}
				}
			}
		}
	}

	// Wait for the seal to be observable before asking the lifecycle to
	// advance. completeSealLocked publishes the finality record synchronously
	// but hands the qpos finalizedEpoch update to a goroutine (, to
	// keep the qpos.mu -> qfs.mu lock order). IsSlotFinalized cross-checks
	// record.Epoch against qpos.GetFinalizedEpoch(), so on the FIRST slot of
	// a new epoch there is a window where the record exists but
	// finalizedEpoch still points at the previous epoch, and IsSlotFinalized
	// transiently answers false.
	//
	// That is what made TestStardustV2_Performance_FinalityDelay flaky in CI
	// under -race: the loop starts at slot 10000 (epoch 312) and slot 10016 is
	// the first slot of epoch 313. Waiting here is the honest fix for the
	// helper, which had assumed finalization was synchronous. The underlying
	// asynchronous-publication question is recorded in the node design notes.
	if qfs := tpf.qpos.GetQTDFinality(); qfs != nil {
		deadline := time.Now().Add(5 * time.Second)
		for !qfs.IsSlotFinalized(slot) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	if err := tpf.CompleteSeal(slot); err != nil {
		return fmt.Errorf("complete seal failed: %w", err)
	}

	if err := tpf.FinalizeBlock(slot); err != nil {
		return fmt.Errorf("finalize failed: %w", err)
	}

	return nil
}

// Compile-time assertion that this file is only compiled during testing.
var _ = testing.T{}

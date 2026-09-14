// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
)

// TestR38P2_03_Supermajority_NotFloored is the RED-regression test for
// audit issue R38-P2-03 (consensus/menxia_review.go:292).
//
// The pre-fix code computed `threshold = floor(2*denominator/3)` and
// accepted the verdict when `ApproveStake >= threshold`. Because `floor`
// rounds DOWN, an approval stake STRICTLY BELOW the true 2/3
// supermajority could lock the verdict — e.g. for N=10
// floor(2*10/3)=6 accepts at 6 (=0.6, not 0.666…), and for N=4
// floor(2*4/3)=2 accepts at 2 (=0.5, not 0.666…). Two of the test cases
// below (N=4 and N=10) FAIL on the floor version and PASS on the
// cross-multiplication fix `3*ApproveStake >= 2*CommitteeTotalStake`,
// hence making this a true RED→GREEN regression test.
//
// The test drives evaluateVerdictLocked directly with a synthetic reviewer
// set of N voters each carrying stake weight 1 (CommitteeTotalStake == N),
// mirroring the conventions of TestR4GOV01_OneVoteLockRegression in
// menxia_review_test.go (same audit family), so the assertion is
// independent of attestation signature verification.
func TestR38P2_03_Supermajority_NotFloored(t *testing.T) {
	// Expected minimal APPROVE stake that locks the verdict Approved under
	// the cross-multiplication semantics `3*approvalStake >= 2*totalStake`
	// (== ceil(2*totalStake/3), the audit-recommended form). For the floor
	// form the minimum would be floor(2*N/3): identical for N∈{3,6,9} but
	// strictly smaller for N∈{4,10} (2 vs 3 and 6 vs 7), which is the exact
	// regression class R38-P2-03 targets.
	cases := []struct {
		n          int64 // committee size; each reviewer has stake weight 1, total == n
		minApprove int64 // smallest ApproveStake that must yield VerdictApproved
	}{
		{n: 3, minApprove: 2},  // ceil(2*3/3)=2  (floor form yields the same value → 2)
		{n: 4, minApprove: 3},  // ceil(8/3)=3   (floor form: 2 → RED point #1)
		{n: 6, minApprove: 4},  // ceil(12/3)=4
		{n: 9, minApprove: 6},  // ceil(18/3)=6
		{n: 10, minApprove: 7}, // ceil(20/3)=7; floor would give 6
	}

	for _, tc := range cases {

		t.Run("", func(t *testing.T) {
			total := big.NewInt(tc.n)

			// (1) minApprove-1 must stay Pending: below the 2/3 ceiling.
			//     For N=4 → approval=2 / N=10 → approval=6, the floor version
			//     would incorrectly transition to Approved → RED.
			if tc.minApprove > 0 {
				below := tc.minApprove - 1
				result := &ReviewSlotResult{
					Slot:                uint64(tc.n),
					CommitteeSize:       int(tc.n),
					ApproveStake:        big.NewInt(below),
					RejectStake:         big.NewInt(0),
					TotalStake:          big.NewInt(below),
					CommitteeTotalStake: new(big.Int).Set(total),
					Verdict:             VerdictPending,
				}
				chamber := NewReviewChamber(nil)
				chamber.mu.Lock()
				chamber.slotResults[result.Slot] = result
				chamber.evaluateVerdictLocked(result)
				chamber.mu.Unlock()

				if result.Verdict != VerdictPending {
					t.Fatalf("R38-P2-03 N=%d approval=%d: expected Pending (ceiling(2*%d/3)=%d), got %s "+
						"— floor(2*%d/3)=%d would have accepted, which is exactly the bug R38-P2-03 forbids",
						tc.n, below, tc.n, tc.minApprove, result.Verdict,
						tc.n, floorTwoThirds(tc.n))
				}
				t.Logf("R38-P2-03 N=%d approval=%d → Pending (below ceiling) PASS", tc.n, below)
			}

			// (2) minApprove must transition to Approved: reaches >= ceil(2/3).
			result := &ReviewSlotResult{
				Slot:                uint64(tc.n) + 1000,
				CommitteeSize:       int(tc.n),
				ApproveStake:        big.NewInt(tc.minApprove),
				RejectStake:         big.NewInt(0),
				TotalStake:          big.NewInt(tc.minApprove),
				CommitteeTotalStake: new(big.Int).Set(total),
				Verdict:             VerdictPending,
			}
			chamber := NewReviewChamber(nil)
			chamber.mu.Lock()
			chamber.slotResults[result.Slot] = result
			chamber.evaluateVerdictLocked(result)
			chamber.mu.Unlock()

			if result.Verdict != VerdictApproved {
				t.Fatalf("R38-P2-03 N=%d approval=%d: expected Approved (>= ceiling(2*%d/3)=%d), got %s",
					tc.n, tc.minApprove, tc.n, tc.minApprove, result.Verdict)
			}
			t.Logf("R38-P2-03 N=%d approval=%d → Approved (meets ceiling) PASS", tc.n, tc.minApprove)
		})
	}

	// Sanity: confirm the cross-mult form differs from the floor form on
	// the two precise N values the audit calls out (N=4, N=10), and is
	// identical on the rest. This makes the RED→GREEN intent explicit.
	type spec struct {
		n                      int64
		wantFloor, wantCeiling int64
	}
	specs := []spec{
		{3, 2, 2},
		{4, 2, 3},
		{6, 4, 4},
		{9, 6, 6},
		{10, 6, 7},
	}
	for _, s := range specs {
		if got := floorTwoThirds(s.n); got != s.wantFloor {
			t.Fatalf("floor sanity n=%d: got %d want %d", s.n, got, s.wantFloor)
		}
		if got := ceilTwoThirds(s.n); got != s.wantCeiling {
			t.Fatalf("ceil sanity n=%d: got %d want %d", s.n, got, s.wantCeiling)
		}
		if s.wantFloor != s.wantCeiling {
			t.Logf("R38-P2-03 divergence confirmed at N=%d: floor=%d ceiling=%d (RED point)", s.n, s.wantFloor, s.wantCeiling)
		}
	}
}

// floorTwoThirds is the buggy pre-fix computation floor(2*n/3); expressed
// here purely so the regression test can reference what the buggy code
// would have accepted. It must NEVER be referenced by production code.
func floorTwoThirds(n int64) int64 { return (2 * n) / 3 }

// ceilTwoThirds is the audit-recommended threshold ceil(2*n/3), which is
// the integer value matched by the cross-multiplication form
// `3*approvalStake >= 2*totalStake`. Used only to assert the expected
// minimum-approval table in the test above.
func ceilTwoThirds(n int64) int64 { return (2*n + 2) / 3 }

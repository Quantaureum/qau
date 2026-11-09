// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// R5-SYNC-THRESHOLD FIX (2026-11-08): the sync committee participation floor
// must be ceil(2n/3). The old formula int(float64(n)*2/3) truncated toward
// zero, so a 6-member committee required only 3 signatures (50%).
func TestMinSyncCommitteeSignaturesCeilTable(t *testing.T) {
	// math.Ceil is an independent oracle for the expected value.
	for n := 1; n <= 16; n++ {
		want := int(math.Ceil(2 * float64(n) / 3))
		if got := MinSyncCommitteeSignatures(n); got != want {
			t.Errorf("MinSyncCommitteeSignatures(%d) = %d, want %d", n, got, want)
		}
	}

	// Fixed boundary points called out by the finding.
	if got := MinSyncCommitteeSignatures(6); got != 4 {
		t.Errorf("MinSyncCommitteeSignatures(6) = %d, want 4", got)
	}
	if got := MinSyncCommitteeSignatures(3); got != 2 {
		t.Errorf("MinSyncCommitteeSignatures(3) = %d, want 2", got)
	}

	// Non-positive committee sizes require no signatures.
	for _, n := range []int{0, -1, -16} {
		if got := MinSyncCommitteeSignatures(n); got != 0 {
			t.Errorf("MinSyncCommitteeSignatures(%d) = %d, want 0", n, got)
		}
	}
}

// TestSyncCommitteeThresholdSixMember pins the required n=6 boundary:
// ceil(2*6/3) = 4, so three signatures must be rejected and four accepted.
//
// Note on the original finding: it claimed the old formula computed 3 for
// n=6. Measured on this toolchain int(float64(6)*(2.0/3.0)) == 4, because
// 2n/3 is exact when n is a multiple of 3. The n=6 case therefore documents
// the required floor but does not reproduce the pre-fix under-count; see
// TestSyncCommitteeThresholdTruncationRepro for the case that does.
func TestSyncCommitteeThresholdSixMember(t *testing.T) {
	v, members := newTestCommittee(t, 6)

	threeSigned := testHeader()
	threeSigned.ChainID = 1668
	threeSigned.Height = 100
	signedHeader(t, threeSigned, []int{0, 1, 2}, members)
	err := v.VerifyBlockHeader(threeSigned)
	if err == nil {
		t.Fatal("3 of 6 signatures accepted: the 2/3 floor is truncated to 1/2")
	}
	if !errors.Is(err, ErrInsufficientSyncSignatures) {
		t.Fatalf("want ErrInsufficientSyncSignatures, got %v", err)
	}
	if !strings.Contains(err.Error(), "need at least 4") {
		t.Fatalf("threshold not applied at verification site: %v", err)
	}

	fourSigned := testHeader()
	fourSigned.ChainID = 1668
	fourSigned.Height = 101
	signedHeader(t, fourSigned, []int{0, 1, 2, 3}, members)
	if err := v.VerifyBlockHeader(fourSigned); err != nil {
		t.Fatalf("4 of 6 signatures rejected: %v", err)
	}
}

// TestSyncCommitteeThresholdTruncationRepro is the genuine pre-fix repro.
// For n=4 the old formula int(float64(4)*2/3) == 2, which accepted 2 of 4
// signatures (50% of the committee). Under ceil(2n/3)=3 the same header must
// be rejected. This test FAILS on the old code.
func TestSyncCommitteeThresholdTruncationRepro(t *testing.T) {
	v, members := newTestCommittee(t, 4)

	twoSigned := testHeader()
	twoSigned.ChainID = 1668
	twoSigned.Height = 102
	signedHeader(t, twoSigned, []int{0, 1}, members)
	err := v.VerifyBlockHeader(twoSigned)
	if err == nil {
		t.Fatal("2 of 4 signatures accepted: the 2/3 floor is truncated to 1/2")
	}
	if !errors.Is(err, ErrInsufficientSyncSignatures) {
		t.Fatalf("want ErrInsufficientSyncSignatures, got %v", err)
	}
	if !strings.Contains(err.Error(), "need at least 3") {
		t.Fatalf("threshold not applied at verification site: %v", err)
	}

	threeSigned := testHeader()
	threeSigned.ChainID = 1668
	threeSigned.Height = 103
	signedHeader(t, threeSigned, []int{0, 1, 2}, members)
	if err := v.VerifyBlockHeader(threeSigned); err != nil {
		t.Fatalf("3 of 4 signatures rejected: %v", err)
	}
}

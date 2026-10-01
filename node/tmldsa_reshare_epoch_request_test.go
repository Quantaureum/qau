// Quantaureum Node source, version 1.0.0.
package node

import "testing"

func TestBuildTMLDSAReshareRunRequestFromEpochRotation(t *testing.T) {
	key, oldCommittee, _, _ := testTMLDSAActivationIdentity(t)
	request, err := buildTMLDSAReshareRunRequest(
		64,
		key,
		oldCommittee,
		[]int{1, 2, 3, 4, 5, 6},
		[]int{7, 8, 9, 10, 11, 12},
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.SessionID == ([32]byte{}) || request.ActivationEpoch != 64 ||
		request.NewCommittee.Version != oldCommittee.Version+1 ||
		len(request.SelectedDealers) != 4 || request.SelectedDealers[3] != 4 {
		t.Fatalf("unexpected request: %+v", request)
	}
	again, err := buildTMLDSAReshareRunRequest(
		64,
		key,
		oldCommittee,
		[]int{1, 2, 3, 4, 5, 6},
		[]int{7, 8, 9, 10, 11, 12},
		4,
	)
	if err != nil || again.SessionID != request.SessionID {
		t.Fatal("epoch request session ID is not deterministic")
	}
	if _, err := buildTMLDSAReshareRunRequest(
		64,
		key,
		oldCommittee,
		[]int{1, 2, 3, 4, 5, 7},
		[]int{7, 8, 9, 10, 11, 12},
		4,
	); err == nil {
		t.Fatal("mismatched old committee accepted")
	}
}

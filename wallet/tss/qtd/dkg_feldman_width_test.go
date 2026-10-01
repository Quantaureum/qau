// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"os"
	"testing"

	"github.com/quantaureum/qau/pedersen"
)

// Regression for the participant-6 VSS failure on the 2026-09 six-node
// testnet: the un-reduced Feldman evaluation P(id) = Σ a_j·id^j was stored as
// int32 and wrapped for large ids. The split must match the exact integer
// evaluation for every participant, the values must genuinely leave the int32
// range for the ids that used to wrap, and the wire round trip plus Pedersen
// VSS must accept the largest id.
func TestFeldmanSplit_MatchesExactEvaluationForLargeIDs(t *testing.T) {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		t.Fatalf("pedersen generator: %v", err)
	}
	s1 := make(PolyVec, Dilithium3L)
	s2 := make(PolyVec, Dilithium3K)
	for pi := range s1 {
		for ci := 0; ci < N; ci++ {
			s1[pi][ci] = int32((pi*7+ci)%9) - 4
		}
	}
	for pi := range s2 {
		for ci := 0; ci < N; ci++ {
			s2[pi][ci] = int32((pi*5+ci)%9) - 4
		}
	}
	const threshold, total = 4, 6
	commitSet, store, err := generateFeldmanCommitmentSet(s1, s2, threshold, []byte("feldman-width-test"), gen)
	if err != nil {
		t.Fatalf("generateFeldmanCommitmentSet: %v", err)
	}
	// Force ring position 0 to maximal coefficients so the evaluation at the
	// largest id deterministically exceeds int32: (Q-1)·(1+6+36+216) > 2^31.
	// Random coefficients only reach that regime with low probability per
	// coefficient (one wrapped coefficient out of 2816 on the testnet), so the
	// commitments for that ring are recomputed to keep the VSS check honest.
	curveOrder := pedersen.CurveOrder()
	forced := &store.s1Polys[0]
	for j := range forced.coefficients {
		forced.coefficients[j] = Q - 1
		val := new(big.Int).SetInt64(int64(Q - 1))
		val.Mod(val, curveOrder)
		copy(commitSet[44+j*48:44+(j+1)*48], gen.Commit(val, forced.blindings[j]).Bytes())
	}

	shares, err := feldmanSplitPolyVec(store.s1Polys, Dilithium3L, threshold, total)
	if err != nil {
		t.Fatalf("feldmanSplitPolyVec: %v", err)
	}

	beyondInt32 := false
	for id := 1; id <= total; id++ {
		for pi := 0; pi < Dilithium3L; pi++ {
			for ci := 0; ci < N; ci++ {
				fp := store.s1Polys[pi*N+ci]
				want := new(big.Int)
				x := big.NewInt(int64(id))
				pow := big.NewInt(1)
				for _, c := range fp.coefficients {
					want.Add(want, new(big.Int).Mul(big.NewInt(int64(c)), pow))
					pow.Mul(pow, x)
				}
				got := shares[id][pi][ci]
				if !want.IsInt64() || want.Int64() != got {
					t.Fatalf("id %d poly %d coeff %d: split %d, exact %s", id, pi, ci, got, want)
				}
				if got > math.MaxInt32 || got < math.MinInt32 {
					beyondInt32 = true
				}
			}
		}
	}
	if !beyondInt32 {
		t.Fatal("no evaluation left the int32 range; the test does not exercise the regression")
	}

	encoded := vecToBytesFull(shares[total])
	decoded, err := vecFromBytesFull(encoded, Dilithium3L)
	if err != nil {
		t.Fatalf("vecFromBytesFull: %v", err)
	}
	for pi := range decoded {
		if decoded[pi] != shares[total][pi] {
			t.Fatalf("wire round trip mismatch in poly %d", pi)
		}
	}
	s1Blind, _, err := computeFeldmanBlindShares(store, total)
	if err != nil {
		t.Fatalf("computeFeldmanBlindShares: %v", err)
	}
	if err := verifyFeldmanShare(commitSet, encoded, s1Blind[total], true, total, threshold, Dilithium3L, Dilithium3K, gen); err != nil {
		t.Fatalf("VSS for participant %d: %v", total, err)
	}

	reduced := reduceFullShareToQ(shares[total])
	for pi := 0; pi < Dilithium3L; pi++ {
		for ci := 0; ci < N; ci++ {
			want := ((shares[total][pi][ci] % Q) + Q) % Q
			if int64(reduced[pi][ci]) != want {
				t.Fatalf("reduction mismatch at poly %d coeff %d: %d, want %d", pi, ci, reduced[pi][ci], want)
			}
		}
	}
}

func TestFeldmanEvaluationFits(t *testing.T) {
	cases := []struct {
		threshold, total int
		want             bool
	}{
		{2, 3, true},
		{4, 6, true},
		{6, 9, true},
		{7, 10, true},
		{10, 15, true},
		{11, 16, false},
		{14, 20, false},
		{0, 3, false},
	}
	for _, tc := range cases {
		if got := feldmanEvaluationFits(tc.threshold, tc.total); got != tc.want {
			t.Errorf("feldmanEvaluationFits(%d, %d) = %v, want %v", tc.threshold, tc.total, got, tc.want)
		}
	}
	if _, err := feldmanSplitPolyVec([]feldmanRingPoly{}, 0, 14, 20); err == nil {
		t.Fatal("feldmanSplitPolyVec accepted a configuration outside the int64 range")
	}
}

// Full in-process DKG with six and nine parties — the committee sizes the
// epoch rotation needs. Before the int64 fix six parties failed at participant
// 6 and nine parties could not complete Round2 at all.
//
// Opt-in only (R123-SCALE-GATE convention, see simulation/scaletest_gate_test.go).
// This runs the full curve-bound Pedersen VSS validation O(n^2 · totalRing ·
// threshold) times in one process: measured ~373s for 6 parties and >15min for
// 9 parties on a dev box, which blows the CI job timeout (ci.yml runs this
// package non-short with -timeout 10m -race). The int32→int64 regression that
// motivated this test is already guarded fast and deterministically by
// TestFeldmanSplit_MatchesExactEvaluationForLargeIDs (participant-6 VSS in the
// sub-second suite); this test only adds the end-to-end multi-round
// convergence assurance, so it is gated behind an explicit opt-in instead of
// running by default.
//
//	go test ./wallet/tss/qtd/                          # safe (gate closed)
//	QAU_SCALE_TESTS=1 go test -run TestRealDistributedDKG_SixAndNineParties -timeout 30m ./wallet/tss/qtd/
func TestRealDistributedDKG_SixAndNineParties(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-party post-quantum DKG takes minutes")
	}
	if os.Getenv("QAU_SCALE_TESTS") != "1" {
		t.Skip("skipping slow multi-party DKG: set QAU_SCALE_TESTS=1 to run it (minutes per case)")
	}
	for _, tc := range []struct{ n, t int }{{6, 4}, {9, 6}} {
		t.Run(fmt.Sprintf("n%d_t%d", tc.n, tc.t), func(t *testing.T) {
			nodes := newBusNodes(t, fmt.Sprintf("dkg-width-%d", tc.n), tc.n)
			runFullRound1(t, nodes, tc.t, tc.n)
			runFullRound2(t, nodes)
			var first []byte
			for _, n := range nodes {
				res, err := n.runner.Finalize()
				if err != nil {
					t.Fatalf("pid %d Finalize: %v", n.pid, err)
				}
				if first == nil {
					first = res.GroupPublicKey.PubKey
				} else if !bytes.Equal(first, res.GroupPublicKey.PubKey) {
					t.Fatalf("pid %d group public key differs", n.pid)
				}
			}
		})
	}
}

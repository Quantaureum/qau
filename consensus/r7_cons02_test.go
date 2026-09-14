// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// CONS-R7-02 (High) — SealedBidLottery.Finalize had no deterministic
// tiebreaker when picking the lowest-VRF-output winner.
//
// Audit source (AUDIT-R7-CONSENSUS-2026-07-17.md, CONS-R7-02):
//   "SealedBidLottery.Finalize lacks a deterministic tiebreaker when
//    picking the lowest VRF output"
//   Location: consensus/sealed_bid.go:384-391
//   "On compareVRFOutput == 0, use address lexicographic order as the
//    tiebreaker"
//
// Fix:
//   1. On equal VRF output, compare the addresses lexicographically
//     (bytes.Compare).
//   2. RevealedAddrs and SlashedAddrs are now sorted for serialisation
//      determinism.
//
// This test covers:
//   1. Two validators with identical VRF outputs → the player with the
//      smaller address wins deterministically.
//   2. Result is stable across runs despite map iteration order.
//   3. RevealedAddrs and SlashedAddrs are sorted.
//   4. A strictly lower VRF output still wins (tiebreaker does not
//      override the primary criterion).

// helper: commit + reveal for an address with a given VRF output
func consR702commitAndReveal(t *testing.T, sbl *SealedBidLottery, addr types.Address, output *PQVRFOutput) {
	t.Helper()
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("CreateSealedBidCommitment(%x): %v", addr, err)
	}
	if err := sbl.SubmitCommit(commit); err != nil {
		t.Fatalf("SubmitCommit(%x): %v", addr, err)
	}
	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      &PQVRFProof{Proof: make([]byte, 64)},
		VRFOutput:     output,
		Nonce:         nonce,
		Timestamp:     time.Now(),
	}
	if err := sbl.submitRevealInternal(reveal); err != nil {
		t.Fatalf("submitRevealInternal(%x): %v", addr, err)
	}
}

// TestCONS_R7_02_VRFTieDeterministic verifies that when two validators
// produce identical VRF outputs, Finalize deterministically selects the
// one with the smaller address (bytes.Compare). Run multiple iterations
// to catch map-iteration-order non-determinism.
func TestCONS_R7_02_VRFTieDeterministic(t *testing.T) {
	addrSmall := types.Address{0x01}
	addrLarge := types.Address{0x02}

	identicalOutput := &PQVRFOutput{}
	for i := range identicalOutput.Value {
		identicalOutput.Value[i] = 0xAB
	}

	for iter := 0; iter < 50; iter++ {
		sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

		consR702commitAndReveal(t, sbl, addrSmall, identicalOutput)
		consR702commitAndReveal(t, sbl, addrLarge, identicalOutput)

		sbl.TransitionToReveal()
		result := sbl.Finalize()

		if result.SelectedAddr != addrSmall {
			t.Fatalf("CONS-R7-02 iter %d: expected addrSmall (%x), got %x — tiebreaker not deterministic",
				iter, addrSmall, result.SelectedAddr)
		}
	}

	t.Logf("CONS-R7-02 OK: 50 iterations, VRF tie always resolved to addrSmall")
}

// TestCONS_R7_02_RevealedAddrsSorted verifies that Finalize returns
// RevealedAddrs in sorted order (by address bytes).
func TestCONS_R7_02_RevealedAddrsSorted(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	addrs := []types.Address{
		{0xFF}, {0x05}, {0x80}, {0x01}, {0x7F},
	}

	for i, addr := range addrs {
		output := &PQVRFOutput{}
		output.Value[0] = byte(i + 1) // Different VRF outputs
		consR702commitAndReveal(t, sbl, addr, output)
	}

	sbl.TransitionToReveal()
	result := sbl.Finalize()

	if len(result.RevealedAddrs) != len(addrs) {
		t.Fatalf("expected %d revealed, got %d", len(addrs), len(result.RevealedAddrs))
	}

	for i := 1; i < len(result.RevealedAddrs); i++ {
		if bytes.Compare(result.RevealedAddrs[i-1][:], result.RevealedAddrs[i][:]) > 0 {
			t.Fatalf("CONS-R7-02: RevealedAddrs not sorted at index %d: %x > %x",
				i, result.RevealedAddrs[i-1], result.RevealedAddrs[i])
		}
	}

	t.Logf("CONS-R7-02 OK: RevealedAddrs sorted (%d addrs)", len(result.RevealedAddrs))
}

// TestCONS_R7_02_SlashedAddrsSorted verifies that Finalize returns
// SlashedAddrs in sorted order.
//
// CONS-R7-09 UPDATE: Finalize now requires ceil(commitCount*2/3) reveals
// before it can complete. The original test used 5 commits + 0 reveals and
// relied on Finalize still returning a result with all 5 slashed. Under the
// new threshold (ceil(5*2/3)=4) Finalize returns nil with 0 reveals. The
// test is updated to use 6 commits + 4 reveals (meeting ceil(6*2/3)=4) with
// 2 committers not revealing, so we still exercise the SlashedAddrs sorting
// path with 2 entries.
func TestCONS_R7_02_SlashedAddrsSorted(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	addrs := []types.Address{
		{0xFF}, {0x05}, {0x80}, {0x01}, {0x7F}, {0x30},
	}

	// Save nonces from commit phase so reveals can match commitment hashes.
	nonces := make(map[types.Address][SealedBidNonceSize]byte, len(addrs))
	for _, addr := range addrs {
		output := &PQVRFOutput{}
		output.Value[0] = 0x01
		commit, nonce, err := CreateSealedBidCommitment(addr, output)
		if err != nil {
			t.Fatalf("CreateSealedBidCommitment(%x): %v", addr, err)
		}
		if err := sbl.SubmitCommit(commit); err != nil {
			t.Fatalf("SubmitCommit(%x): %v", addr, err)
		}
		nonces[addr] = nonce
	}

	sbl.TransitionToReveal()
	// Reveal the first 4 addrs to meet the ceil(6*2/3)=4 threshold.
	// The remaining 2 addrs ({0x7F}, {0x30}) are NOT revealed → slashed.
	// Each reveal must reuse the nonce from the matching commit so the
	// commitment hash matches (submitRevealInternal verifies this).
	for _, addr := range addrs[:4] {
		output := &PQVRFOutput{}
		output.Value[0] = 0x01
		reveal := &SealedBidReveal{
			ValidatorAddr: addr,
			VRFProof:      &PQVRFProof{Proof: make([]byte, 64)},
			VRFOutput:     output,
			Nonce:         nonces[addr],
			Timestamp:     time.Now(),
		}
		if err := sbl.submitRevealInternal(reveal); err != nil {
			t.Fatalf("submitRevealInternal(%x): %v", addr, err)
		}
	}
	result := sbl.Finalize()
	if result == nil {
		t.Fatalf("Finalize returned nil despite meeting the 2/3 reveal threshold")
	}

	if len(result.SlashedAddrs) != 2 {
		t.Fatalf("expected 2 slashed, got %d", len(result.SlashedAddrs))
	}

	for i := 1; i < len(result.SlashedAddrs); i++ {
		if bytes.Compare(result.SlashedAddrs[i-1][:], result.SlashedAddrs[i][:]) > 0 {
			t.Fatalf("CONS-R7-02: SlashedAddrs not sorted at index %d: %x > %x",
				i, result.SlashedAddrs[i-1], result.SlashedAddrs[i])
		}
	}

	t.Logf("CONS-R7-02 OK: SlashedAddrs sorted (%d addrs)", len(result.SlashedAddrs))
}

// TestCONS_R7_02_LowerVRFStillWins verifies that the tiebreaker does NOT
// override the primary selection criterion (lowest VRF output).
func TestCONS_R7_02_LowerVRFStillWins(t *testing.T) {
	addrSmall := types.Address{0x01}
	addrLarge := types.Address{0x02}

	lowerOutput := &PQVRFOutput{}
	lowerOutput.Value[0] = 0x00

	higherOutput := &PQVRFOutput{}
	higherOutput.Value[0] = 0xFF

	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	// addrSmall has HIGHER output (should lose); addrLarge has LOWER (should win)
	consR702commitAndReveal(t, sbl, addrSmall, higherOutput)
	consR702commitAndReveal(t, sbl, addrLarge, lowerOutput)

	sbl.TransitionToReveal()
	result := sbl.Finalize()

	if result.SelectedAddr != addrLarge {
		t.Fatalf("CONS-R7-02: addrLarge has lower VRF and must win; got %x", result.SelectedAddr)
	}

	t.Logf("CONS-R7-02 OK: lower VRF output wins over address tiebreaker")
}

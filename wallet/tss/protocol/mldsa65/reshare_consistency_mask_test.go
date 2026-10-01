// Quantaureum Node source, version 1.0.0.
package mldsa65

import "testing"

func TestResharePairwiseMasksCancel(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x39
	participants := []uint32{7, 8, 9, 10, 11, 12}
	totals := make(map[uint32]int64, len(participants))
	for leftIndex := 0; leftIndex < len(participants); leftIndex++ {
		for rightIndex := leftIndex + 1; rightIndex < len(participants); rightIndex++ {
			left := participants[leftIndex]
			right := participants[rightIndex]
			var sharedSecret [32]byte
			sharedSecret[0] = byte(left)
			sharedSecret[1] = byte(right)
			leftMask, err := DeriveResharePairwiseMask(sessionID, 2, 3, 1, left, right, sharedSecret)
			if err != nil {
				t.Fatalf("left mask %d-%d: %v", left, right, err)
			}
			rightMask, err := DeriveResharePairwiseMask(sessionID, 2, 3, 1, right, left, sharedSecret)
			if err != nil {
				t.Fatalf("right mask %d-%d: %v", left, right, err)
			}
			if leftMask+rightMask != 0 {
				t.Fatalf("pair %d-%d masks do not cancel: %d %d", left, right, leftMask, rightMask)
			}
			totals[left] += int64(leftMask)
			totals[right] += int64(rightMask)
		}
	}
	var aggregate int64
	for _, participantID := range participants {
		aggregate += totals[participantID]
	}
	if aggregate != 0 {
		t.Fatalf("aggregate pairwise mask = %d", aggregate)
	}
}

func TestResharePairwiseMaskDomainSeparation(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x4a
	var sharedSecret [32]byte
	sharedSecret[0] = 0x5b
	base, err := DeriveResharePairwiseMask(sessionID, 1, 0, 0, 7, 8, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	differentRound, err := DeriveResharePairwiseMask(sessionID, 1, 1, 0, 7, 8, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	differentCheck, err := DeriveResharePairwiseMask(sessionID, 1, 0, 1, 7, 8, sharedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if base == differentRound || base == differentCheck || differentRound == differentCheck {
		t.Fatal("pairwise mask domains collided")
	}
}

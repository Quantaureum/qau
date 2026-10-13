// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Secret erasure helpers. Each one zeroizes through its argument inside a
// function the compiler may not inline, so the stores cannot be removed as dead
// even when the caller never reads the buffer again. Erasure is best effort:
// the Go runtime can copy a goroutine stack when it grows, and the old copy is
// not cleared.

//go:noinline
func wipeBytes(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}

//go:noinline
func wipeFloat64s(buffer []float64) {
	for index := range buffer {
		buffer[index] = 0
	}
}

//go:noinline
func wipePolys(polys []Poly) {
	for index := range polys {
		polys[index] = Poly{}
	}
}

//go:noinline
func wipeSignedPolys(polys []SignedPoly) {
	for index := range polys {
		polys[index] = SignedPoly{}
	}
}

// wipe zeroizes the ball point: the raw sample and its rounded expansion.
func (point *signingRandomness) wipe() {
	if point == nil {
		return
	}
	wipeFloat64s(point.raw[:])
	wipePolys(point.first[:])
	wipePolys(point.second[:])
}

// clone returns an independent copy of the ball point, so each signer owns and
// erases its own.
func (point *signingRandomness) clone() *signingRandomness {
	if point == nil {
		return nil
	}
	copied := *point
	return &copied
}

// rssComponentsEqualConstantTime compares two components, secret vectors
// included, without exiting at the first differing coefficient.
func rssComponentsEqualConstantTime(left, right RSSComponent) bool {
	var difference Coefficient
	for row := 0; row < L; row++ {
		for index := 0; index < N; index++ {
			difference |= left.S1[row][index] ^ right.S1[row][index]
		}
	}
	for row := 0; row < K; row++ {
		for index := 0; index < N; index++ {
			difference |= left.S2[row][index] ^ right.S2[row][index]
		}
	}
	public := left.GroupMask == right.GroupMask && left.DealerPosition == right.DealerPosition &&
		left.ContributionDigest == right.ContributionDigest && left.Multiplicity == right.Multiplicity
	return difference == 0 && public
}

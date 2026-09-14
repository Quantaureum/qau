// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/pedersen"
)

var ErrDKGVSSVerification = errors.New("dkg: VSS verification failed: share does not match commitment set")

type feldmanRingPoly struct {
	coefficients []int32
	blindings    []*big.Int
}

type feldmanBlindStore struct {
	threshold int
	s1Polys   []feldmanRingPoly
	s2Polys   []feldmanRingPoly
}

func generateFeldmanCommitmentSet(s1, s2 PolyVec, threshold int, sessionID []byte, gen *pedersen.Generator) ([]byte, *feldmanBlindStore, error) {
	if threshold < 2 {
		return nil, nil, ErrDKGInvalidThreshold
	}
	s1PolyCount := len(s1)
	s2PolyCount := len(s2)
	totalRing := s1PolyCount*N + s2PolyCount*N

	store := &feldmanBlindStore{
		threshold: threshold,
		s1Polys:   make([]feldmanRingPoly, s1PolyCount*N),
		s2Polys:   make([]feldmanRingPoly, s2PolyCount*N),
	}

	header := make([]byte, 44)
	binary.LittleEndian.PutUint32(header[0:4], uint32(s1PolyCount))
	binary.LittleEndian.PutUint32(header[4:8], uint32(s2PolyCount))
	binary.LittleEndian.PutUint32(header[8:12], uint32(threshold))
	copy(header[12:44], sessionID)

	body := make([]byte, 0, totalRing*threshold*48)

	curveOrder := pedersen.CurveOrder()

	processRing := func(polyStore []feldmanRingPoly, vec PolyVec, polyCount int) error {
		for pi := 0; pi < polyCount; pi++ {
			for ci := 0; ci < N; ci++ {
				idx := pi*N + ci
				secret := int64(vec[pi][ci])
				fp := feldmanRingPoly{
					coefficients: make([]int32, threshold),
					blindings:    make([]*big.Int, threshold),
				}
				fp.coefficients[0] = int32(secret)

				for j := 1; j < threshold; j++ {
					c, err := randCoeffQ()
					if err != nil {
						return fmt.Errorf("generate random coefficient: %w", err)
					}
					fp.coefficients[j] = c
				}
				for j := 0; j < threshold; j++ {
					r, err := pedersen.RandomBlinding()
					if err != nil {
						return fmt.Errorf("generate blinding: %w", err)
					}
					fp.blindings[j] = r
				}
				polyStore[idx] = fp

				for j := 0; j < threshold; j++ {
					val := new(big.Int).SetInt64(int64(fp.coefficients[j]))
					val.Mod(val, curveOrder)
					comm := gen.Commit(val, fp.blindings[j])
					body = append(body, comm.Bytes()...)
				}
			}
		}
		return nil
	}

	if err := processRing(store.s1Polys, s1, s1PolyCount); err != nil {
		zeroizeFeldmanStore(store)
		return nil, nil, err
	}
	if err := processRing(store.s2Polys, s2, s2PolyCount); err != nil {
		zeroizeFeldmanStore(store)
		return nil, nil, err
	}

	return append(header, body...), store, nil
}

func validateFeldmanCommitmentSet(data []byte, expectedSessionID []byte, expectedS1Count, expectedS2Count, expectedThreshold int) error {
	if len(data) < 44 {
		return fmt.Errorf("%w: commitment set too short: %d bytes", ErrDKGWrongSession, len(data))
	}
	s1Count := int(binary.LittleEndian.Uint32(data[0:4]))
	s2Count := int(binary.LittleEndian.Uint32(data[4:8]))
	threshold := int(binary.LittleEndian.Uint32(data[8:12]))
	if s1Count != expectedS1Count {
		return fmt.Errorf("dkg: commitment s1PolyCount %d, want %d", s1Count, expectedS1Count)
	}
	if s2Count != expectedS2Count {
		return fmt.Errorf("dkg: commitment s2PolyCount %d, want %d", s2Count, expectedS2Count)
	}
	if threshold != expectedThreshold {
		return fmt.Errorf("dkg: commitment threshold %d, want %d", threshold, expectedThreshold)
	}
	sessionID := data[12:44]
	padded := make([]byte, 32)
	copy(padded, expectedSessionID)
	if !bytesEqual(sessionID, padded) {
		return ErrDKGWrongSession
	}
	totalRing := s1Count*N + s2Count*N
	expectedBody := totalRing * threshold * 48
	if len(data[44:]) != expectedBody {
		return fmt.Errorf("dkg: commitment body length %d, want %d (totalRing=%d threshold=%d)", len(data[44:]), expectedBody, totalRing, threshold)
	}
	for i := 0; i < totalRing*threshold; i++ {
		off := 44 + i*48
		if _, err := pedersen.CommitmentFromBytes(data[off : off+48]); err != nil {
			return fmt.Errorf("dkg: commitment point %d: %w", i, err)
		}
	}
	return nil
}

// feldmanSplitPolyVec performs Shamir splitting using the polynomial coefficients stored in feldmanStore,
// ensuring the shares and commitments use the same polynomial (fixes the VSS verification failure bug).
// polyStore is either store.s1Polys or store.s2Polys.
//
// Key point: this computes the full integer evaluation (no mod Q), because Pedersen VSS verification needs
// the complete P(id) = sum(coeff_j * id^j) value (scalar multiplication on the BLS12-381 curve),
// not the mod-Q value Dilithium uses. Callers reduce mod Q themselves after VSS verification.
func feldmanSplitPolyVec(polyStore []feldmanRingPoly, polyCount, threshold, total int) (map[int]PolyVec, error) {
	if polyStore == nil {
		return nil, errors.New("dkg: feldmanRingPoly store is nil")
	}
	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, polyCount)
	}
	for pi := 0; pi < polyCount; pi++ {
		for ci := 0; ci < N; ci++ {
			idx := pi*N + ci
			if idx >= len(polyStore) {
				return nil, fmt.Errorf("dkg: feldman store index %d out of range (len=%d)", idx, len(polyStore))
			}
			fp := polyStore[idx]
			if len(fp.coefficients) < threshold {
				return nil, fmt.Errorf("dkg: feldman poly has %d coeffs, want %d", len(fp.coefficients), threshold)
			}
			for id := 1; id <= total; id++ {
				x := int64(id)
				xPow := int64(1)
				val := int64(0)
				for _, coeff := range fp.coefficients {
					val = val + int64(coeff)*xPow
					xPow = xPow * x
				}
				shares[id][pi][ci] = int32(val)
			}
		}
	}
	return shares, nil
}

func computeFeldmanBlindShares(store *feldmanBlindStore, total int) (map[int][]byte, map[int][]byte, error) {
	if store == nil {
		return nil, nil, errors.New("dkg: feldmanBlindStore is nil")
	}
	curveOrder := pedersen.CurveOrder()
	s1BlindShares := make(map[int][]byte, total)
	s2BlindShares := make(map[int][]byte, total)

	for pid := 1; pid <= total; pid++ {
		idBig := big.NewInt(int64(pid))

		s1Blind := make([]byte, len(store.s1Polys)*32)
		for i, fp := range store.s1Polys {
			rID := evalBlindPoly(fp.blindings, idBig, curveOrder)
			rID.FillBytes(s1Blind[i*32 : (i+1)*32])
		}
		s1BlindShares[pid] = s1Blind

		s2Blind := make([]byte, len(store.s2Polys)*32)
		for i, fp := range store.s2Polys {
			rID := evalBlindPoly(fp.blindings, idBig, curveOrder)
			rID.FillBytes(s2Blind[i*32 : (i+1)*32])
		}
		s2BlindShares[pid] = s2Blind
	}
	return s1BlindShares, s2BlindShares, nil
}

func verifyFeldmanShare(commitmentSet []byte, shareBytes []byte, blindShareBytes []byte, isS1 bool, participantID int, threshold int, s1PolyCount int, s2PolyCount int, gen *pedersen.Generator) error {
	s1PolyCount = Dilithium3L
	s2PolyCount = Dilithium3K
	if threshold < 2 {
		return ErrDKGInvalidThreshold
	}
	if participantID < 1 {
		return ErrDKGUnknownParticipant
	}

	var polyCount int
	var coeffOffset int
	if isS1 {
		polyCount = s1PolyCount
		coeffOffset = 0
	} else {
		polyCount = s2PolyCount
		coeffOffset = s1PolyCount * N
	}

	expectedShareLen := polyCount * N * 4
	expectedBlindLen := polyCount * N * 32
	if len(shareBytes) != expectedShareLen {
		return fmt.Errorf("%w: share length %d, want %d", ErrDKGVSSVerification, len(shareBytes), expectedShareLen)
	}
	if len(blindShareBytes) != expectedBlindLen {
		return fmt.Errorf("%w: blind share length %d, want %d", ErrDKGVSSVerification, len(blindShareBytes), expectedBlindLen)
	}
	if len(commitmentSet) < 44 {
		return fmt.Errorf("%w: commitment set too short", ErrDKGVSSVerification)
	}

	curveOrder := pedersen.CurveOrder()
	idBig := big.NewInt(int64(participantID))
	powerCache := make([]*big.Int, threshold)
	powerCache[0] = big.NewInt(1)
	for j := 1; j < threshold; j++ {
		powerCache[j] = new(big.Int).Exp(idBig, big.NewInt(int64(j)), nil)
	}

	for ri := 0; ri < polyCount*N; ri++ {
		globalIdx := coeffOffset + ri

		shareVal := int32(binary.LittleEndian.Uint32(shareBytes[ri*4 : ri*4+4]))
		shareBig := new(big.Int).SetInt64(int64(shareVal))
		shareBig.Mod(shareBig, curveOrder)

		blindBig := new(big.Int).SetBytes(blindShareBytes[ri*32 : (ri+1)*32])

		lhs := gen.Commit(shareBig, blindBig)

		commitOff := 44 + globalIdx*threshold*48
		c0, err := pedersen.CommitmentFromBytes(commitmentSet[commitOff : commitOff+48])
		if err != nil {
			return fmt.Errorf("%w: commitment point at ring %d: %v", ErrDKGVSSVerification, ri, err)
		}
		rhs := gen.ScalarMulCommitment(c0, powerCache[0])
		for j := 1; j < threshold; j++ {
			cj, err := pedersen.CommitmentFromBytes(commitmentSet[commitOff+j*48 : commitOff+(j+1)*48])
			if err != nil {
				return fmt.Errorf("%w: commitment point %d at ring %d: %v", ErrDKGVSSVerification, j, ri, err)
			}
			scaled := gen.ScalarMulCommitment(cj, powerCache[j])
			rhs = gen.HomomorphicAdd(rhs, scaled)
		}

		if !lhs.Equal(rhs) {
			return fmt.Errorf("%w: ring coefficient %d (global %d)", ErrDKGVSSVerification, ri, globalIdx)
		}
	}
	return nil
}

func zeroizeFeldmanStore(store *feldmanBlindStore) {
	if store == nil {
		return
	}
	for i := range store.s1Polys {
		for j := range store.s1Polys[i].blindings {
			store.s1Polys[i].blindings[j] = nil
		}
		store.s1Polys[i].blindings = nil
		store.s1Polys[i].coefficients = nil
	}
	store.s1Polys = nil
	for i := range store.s2Polys {
		for j := range store.s2Polys[i].blindings {
			store.s2Polys[i].blindings[j] = nil
		}
		store.s2Polys[i].blindings = nil
		store.s2Polys[i].coefficients = nil
	}
	store.s2Polys = nil
}

func evalBlindPoly(blindings []*big.Int, id *big.Int, curveOrder *big.Int) *big.Int {
	result := new(big.Int)
	power := new(big.Int).SetInt64(1)
	for _, r := range blindings {
		term := new(big.Int).Mul(r, power)
		result.Add(result, term)
		power.Mul(power, id)
		power.Mod(power, curveOrder)
	}
	result.Mod(result, curveOrder)
	return result
}

func randCoeffQ() (int32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("rand read: %w", err)
	}
	return int32(binary.LittleEndian.Uint32(buf[:]) % uint32(Q)), nil
}

// vecToBytesFull serializes a PolyVec with 4 bytes per coefficient (signed int32 LE).
// Used for VSS shares that carry full integer evaluation (not modulo Q).
func vecToBytesFull(v PolyVec) []byte {
	out := make([]byte, len(v)*N*4)
	for pi := range v {
		for ci := 0; ci < N; ci++ {
			off := (pi*N + ci) * 4
			val := uint32(v[pi][ci])
			binary.LittleEndian.PutUint32(out[off:off+4], val)
		}
	}
	return out
}

// vecFromBytesFull deserializes a PolyVec from 4 bytes per coefficient (signed int32 LE).
func vecFromBytesFull(b []byte, numPolys int) (PolyVec, error) {
	if len(b) != numPolys*N*4 {
		return nil, ErrInvalidPolyBytes
	}
	vec := make(PolyVec, numPolys)
	for pi := 0; pi < numPolys; pi++ {
		for ci := 0; ci < N; ci++ {
			off := (pi*N + ci) * 4
			vec[pi][ci] = int32(binary.LittleEndian.Uint32(b[off : off+4]))
		}
	}
	return vec, nil
}

// reduceFullShareToQ reduces each coefficient of a full-integer PolyVec modulo Q,
// producing a standard PolyVec with coefficients in [0, Q-1].
func reduceFullShareToQ(v PolyVec) PolyVec {
	out := make(PolyVec, len(v))
	for pi := range v {
		for ci := 0; ci < N; ci++ {
			out[pi][ci] = int32(((int64(v[pi][ci]) % Q) + Q) % Q)
		}
	}
	return out
}

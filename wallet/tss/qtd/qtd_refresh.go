// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

type RefreshDeltas struct {
	ParticipantID int
	S1Deltas      map[int]PolyVec
	S2Deltas      map[int]PolyVec
	T0Deltas      map[int]PolyVec
	Commitment    []byte
}

type RefreshCommitment struct {
	ParticipantID int
	Hash          []byte
}

type RefreshReveal struct {
	ParticipantID int
	Deltas        map[int]*ShareDelta
}

type ShareDelta struct {
	S1Delta []byte
	S2Delta []byte
	T0Delta []byte
}

type RefreshResult struct {
	UpdatedShares []*QTDShare
	Success       bool
}

func GenerateRefreshDeltas(participantID int, allParticipantIDs []int, numS1Polys, numS2Polys, numT0Polys int) (*RefreshDeltas, error) {
	if len(allParticipantIDs) == 0 {
		return nil, ErrInvalidConfig
	}

	s1Deltas := make(map[int]PolyVec, len(allParticipantIDs))
	s2Deltas := make(map[int]PolyVec, len(allParticipantIDs))
	t0Deltas := make(map[int]PolyVec, len(allParticipantIDs))

	for _, id := range allParticipantIDs {
		s1Deltas[id] = make(PolyVec, numS1Polys)
		s2Deltas[id] = make(PolyVec, numS2Polys)
		t0Deltas[id] = make(PolyVec, numT0Polys)
	}

	if err := generateZeroSumDeltas(s1Deltas, allParticipantIDs, numS1Polys); err != nil {
		return nil, fmt.Errorf("s1 delta generation failed: %w", err)
	}
	if err := generateZeroSumDeltas(s2Deltas, allParticipantIDs, numS2Polys); err != nil {
		return nil, fmt.Errorf("s2 delta generation failed: %w", err)
	}
	if err := generateZeroSumDeltas(t0Deltas, allParticipantIDs, numT0Polys); err != nil {
		return nil, fmt.Errorf("t0 delta generation failed: %w", err)
	}

	h := sha256.New()
	h.Write([]byte("QTD_REFRESH_V1"))
	h.Write([]byte{byte(participantID)})
	for _, id := range allParticipantIDs {
		h.Write(VecToBytes(s1Deltas[id]))
		h.Write(VecToBytes(s2Deltas[id]))
		h.Write(VecToBytes(t0Deltas[id]))
	}
	commitment := h.Sum(nil)

	return &RefreshDeltas{
		ParticipantID: participantID,
		S1Deltas:      s1Deltas,
		S2Deltas:      s2Deltas,
		T0Deltas:      t0Deltas,
		Commitment:    commitment,
	}, nil
}

func generateZeroSumDeltas(deltas map[int]PolyVec, ids []int, numPolys int) error {
	n := len(ids)
	if n == 0 {
		return ErrInvalidConfig
	}

	for p := 0; p < numPolys; p++ {
		for c := 0; c < N; c++ {
			sum := int64(0)
			for i := 0; i < n-1; i++ {
				var buf [4]byte
				if _, err := rand.Read(buf[:]); err != nil {
					return fmt.Errorf("random generation failed: %w", err)
				}
				val := int64(binary.LittleEndian.Uint32(buf[:])) % Q
				deltas[ids[i]][p][c] = int32(val)
				sum = (sum + val) % Q
			}
			lastVal := (Q - sum) % Q
			deltas[ids[n-1]][p][c] = int32(lastVal)
		}
	}

	return nil
}

func ComputeRefreshCommitment(deltas *RefreshDeltas) []byte {
	h := sha256.New()
	h.Write([]byte("QTD_REFRESH_V1"))
	h.Write([]byte{byte(deltas.ParticipantID)})

	ids := make([]int, 0, len(deltas.S1Deltas))
	for id := range deltas.S1Deltas {
		ids = append(ids, id)
	}
	for i := 0; i < len(ids)-1; i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] > ids[j] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}

	for _, id := range ids {
		h.Write(VecToBytes(deltas.S1Deltas[id]))
		h.Write(VecToBytes(deltas.S2Deltas[id]))
		h.Write(VecToBytes(deltas.T0Deltas[id]))
	}
	return h.Sum(nil)
}

func VerifyRefreshCommitment(deltas *RefreshDeltas) bool {
	expected := ComputeRefreshCommitment(deltas)
	return subtle.ConstantTimeCompare(expected, deltas.Commitment) == 1
}

func ApplyRefreshDeltas(shares []*QTDShare, allDeltas []*RefreshDeltas) ([]*QTDShare, error) {
	if len(shares) == 0 || len(allDeltas) == 0 {
		return nil, ErrInvalidConfig
	}

	for _, d := range allDeltas {
		if !VerifyRefreshCommitment(d) {
			return nil, fmt.Errorf("%w: participant %d commitment mismatch", ErrRefreshFailed, d.ParticipantID)
		}
	}

	// AUDIT (2026) TSS-FIX: Verify that each sender's refresh
	// deltas sum to zero across all recipients. In proactive secret sharing,
	// each participant generates random deltas for all other participants
	// such that their sum is zero — this preserves the group secret while
	// randomizing individual shares. Without this check, a malicious
	// participant could submit non-zero-sum deltas, silently shifting the
	// group key and causing all future signatures to fail (liveness/DoS).
	// The invariant: for each sender d, sum of d.S1Deltas[*] = 0, etc.
	for _, d := range allDeltas {
		var s1Sum, s2Sum, t0Sum PolyVec
		first := true
		for pid, s1Delta := range d.S1Deltas {
			s2Delta, ok := d.S2Deltas[pid]
			if !ok {
				return nil, fmt.Errorf("%w: sender %d: missing s2 delta for recipient %d", ErrRefreshFailed, d.ParticipantID, pid)
			}
			t0Delta, ok := d.T0Deltas[pid]
			if !ok {
				return nil, fmt.Errorf("%w: sender %d: missing t0 delta for recipient %d", ErrRefreshFailed, d.ParticipantID, pid)
			}
			if first {
				s1Sum = s1Delta
				s2Sum = s2Delta
				t0Sum = t0Delta
				first = false
			} else {
				s1Sum = VecAdd(s1Sum, s1Delta)
				s2Sum = VecAdd(s2Sum, s2Delta)
				t0Sum = VecAdd(t0Sum, t0Delta)
			}
		}
		if !isPolyVecZero(s1Sum) || !isPolyVecZero(s2Sum) || !isPolyVecZero(t0Sum) {
			return nil, fmt.Errorf("%w: sender %d's delta sum is non-zero — group key would be corrupted", ErrRefreshFailed, d.ParticipantID)
		}
	}

	updatedShares := make([]*QTDShare, len(shares))
	for i, share := range shares {
		// Q21-005 FIX: Validate old share integrity before applying refresh.
		// Shares with missing S1/S2/T0 bytes cannot be safely refreshed.
		if len(share.S1ShareBytes) == 0 {
			return nil, fmt.Errorf("share %d has empty S1ShareBytes", share.ParticipantID)
		}
		if len(share.S2ShareBytes) == 0 {
			return nil, fmt.Errorf("share %d has empty S2ShareBytes", share.ParticipantID)
		}
		if len(share.T0ShareBytes) == 0 {
			return nil, fmt.Errorf("share %d has empty T0ShareBytes", share.ParticipantID)
		}
		newShare := &QTDShare{
			ParticipantID: share.ParticipantID,
			Rho:           make([]byte, len(share.Rho)),
			T1Bytes:       make([]byte, len(share.T1Bytes)),
		}
		copy(newShare.Rho, share.Rho)
		copy(newShare.T1Bytes, share.T1Bytes)

		s1Vec, err := VecFromBytes(share.S1ShareBytes, Dilithium3L)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize s1 share: %w", err)
		}
		s2Vec, err := VecFromBytes(share.S2ShareBytes, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize s2 share: %w", err)
		}
		t0Vec, err := VecFromBytes(share.T0ShareBytes, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize t0 share: %w", err)
		}

		for _, d := range allDeltas {
			s1Delta, ok := d.S1Deltas[share.ParticipantID]
			if !ok {
				return nil, fmt.Errorf("%w: no s1 delta for participant %d from %d", ErrRefreshFailed, share.ParticipantID, d.ParticipantID)
			}
			s2Delta, ok := d.S2Deltas[share.ParticipantID]
			if !ok {
				return nil, fmt.Errorf("%w: no s2 delta for participant %d from %d", ErrRefreshFailed, share.ParticipantID, d.ParticipantID)
			}
			t0Delta, ok := d.T0Deltas[share.ParticipantID]
			if !ok {
				return nil, fmt.Errorf("%w: no t0 delta for participant %d from %d", ErrRefreshFailed, share.ParticipantID, d.ParticipantID)
			}

			s1Vec = VecAdd(s1Vec, s1Delta)
			s2Vec = VecAdd(s2Vec, s2Delta)
			t0Vec = VecAdd(t0Vec, t0Delta)
		}

		newShare.S1ShareBytes = VecToBytes(s1Vec)
		newShare.S2ShareBytes = VecToBytes(s2Vec)
		newShare.T0ShareBytes = VecToBytes(t0Vec)

		// FIX: Zero the deserialized polynomial vectors after use.
		// These contain private key material (old shares + refresh deltas)
		// and must not remain in memory after serialization.
		for j := range s1Vec {
			s1Vec[j].Zero()
		}
		for j := range s2Vec {
			s2Vec[j].Zero()
		}
		for j := range t0Vec {
			t0Vec[j].Zero()
		}

		vVector, err := generateVerificationVector(newShare.S1ShareBytes, len(shares))
		if err != nil {
			return nil, fmt.Errorf("failed to generate verification vector: %w", err)
		}
		newShare.VVector = vVector

		vVectorS2, errS2 := generateVerificationVector(newShare.S2ShareBytes, len(shares))
		if errS2 != nil {
			return nil, fmt.Errorf("failed to generate S2 verification vector: %w", errS2)
		}
		newShare.VVectorS2 = vVectorS2

		vVectorT0, errT0 := generateVerificationVector(newShare.T0ShareBytes, len(shares))
		if errT0 != nil {
			return nil, fmt.Errorf("failed to generate T0 verification vector: %w", errT0)
		}
		newShare.VVectorT0 = vVectorT0

		updatedShares[i] = newShare
	}

	return updatedShares, nil
}

func VerifyRefreshIntegrity(oldShares, newShares []*QTDShare) error {
	if len(oldShares) != len(newShares) {
		return fmt.Errorf("%w: share count mismatch", ErrRefreshFailed)
	}

	for i := range oldShares {
		oldS1, err := VecFromBytes(oldShares[i].S1ShareBytes, Dilithium3L)
		if err != nil {
			return fmt.Errorf("old s1 deserialize failed: %w", err)
		}
		oldS2, err := VecFromBytes(oldShares[i].S2ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("old s2 deserialize failed: %w", err)
		}
		oldT0, err := VecFromBytes(oldShares[i].T0ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("old t0 deserialize failed: %w", err)
		}

		newS1, err := VecFromBytes(newShares[i].S1ShareBytes, Dilithium3L)
		if err != nil {
			return fmt.Errorf("new s1 deserialize failed: %w", err)
		}
		newS2, err := VecFromBytes(newShares[i].S2ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("new s2 deserialize failed: %w", err)
		}
		newT0, err := VecFromBytes(newShares[i].T0ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("new t0 deserialize failed: %w", err)
		}

		if VecNormInf(VecAdd(oldS1, VecScalarMul(newS1, -1))) == 0 &&
			VecNormInf(VecAdd(oldS2, VecScalarMul(newS2, -1))) == 0 &&
			VecNormInf(VecAdd(oldT0, VecScalarMul(newT0, -1))) == 0 {
			return fmt.Errorf("%w: participant %d share unchanged after refresh", ErrRefreshFailed, oldShares[i].ParticipantID)
		}
	}

	return nil
}

func VerifySecretPreservation(oldShares, newShares []*QTDShare) error {
	if len(oldShares) != len(newShares) {
		return fmt.Errorf("%w: share count mismatch", ErrRefreshFailed)
	}

	oldS1Sum := make(PolyVec, Dilithium3L)
	newS1Sum := make(PolyVec, Dilithium3L)
	oldS2Sum := make(PolyVec, Dilithium3K)
	newS2Sum := make(PolyVec, Dilithium3K)
	oldT0Sum := make(PolyVec, Dilithium3K)
	newT0Sum := make(PolyVec, Dilithium3K)

	for i := range oldShares {
		// FIX: Check all VecFromBytes errors instead of ignoring them.
		oldS1, err := VecFromBytes(oldShares[i].S1ShareBytes, Dilithium3L)
		if err != nil {
			return fmt.Errorf("%w: old s1 deserialize failed: %w", ErrRefreshFailed, err)
		}
		newS1, err := VecFromBytes(newShares[i].S1ShareBytes, Dilithium3L)
		if err != nil {
			return fmt.Errorf("%w: new s1 deserialize failed: %w", ErrRefreshFailed, err)
		}
		oldS2, err := VecFromBytes(oldShares[i].S2ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("%w: old s2 deserialize failed: %w", ErrRefreshFailed, err)
		}
		newS2, err := VecFromBytes(newShares[i].S2ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("%w: new s2 deserialize failed: %w", ErrRefreshFailed, err)
		}
		oldT0, err := VecFromBytes(oldShares[i].T0ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("%w: old t0 deserialize failed: %w", ErrRefreshFailed, err)
		}
		newT0, err := VecFromBytes(newShares[i].T0ShareBytes, Dilithium3K)
		if err != nil {
			return fmt.Errorf("%w: new t0 deserialize failed: %w", ErrRefreshFailed, err)
		}

		oldS1Sum = VecAdd(oldS1Sum, oldS1)
		newS1Sum = VecAdd(newS1Sum, newS1)
		oldS2Sum = VecAdd(oldS2Sum, oldS2)
		newS2Sum = VecAdd(newS2Sum, newS2)
		oldT0Sum = VecAdd(oldT0Sum, oldT0)
		newT0Sum = VecAdd(newT0Sum, newT0)
	}

	if VecNormInf(VecAdd(oldS1Sum, VecScalarMul(newS1Sum, -1))) != 0 {
		return fmt.Errorf("%w: s1 secret not preserved after refresh", ErrRefreshFailed)
	}
	if VecNormInf(VecAdd(oldS2Sum, VecScalarMul(newS2Sum, -1))) != 0 {
		return fmt.Errorf("%w: s2 secret not preserved after refresh", ErrRefreshFailed)
	}
	if VecNormInf(VecAdd(oldT0Sum, VecScalarMul(newT0Sum, -1))) != 0 {
		return fmt.Errorf("%w: t0 secret not preserved after refresh", ErrRefreshFailed)
	}

	return nil
}

type SubShare struct {
	FromParticipant int
	ToParticipant   int
	S1SubShare      []byte
	S2SubShare      []byte
	T0SubShare      []byte
}

type ReshareResult struct {
	NewShares         []*QTDShare
	NewThreshold      int
	NewTotal          int
	NewParticipantIDs []int
}

func GenerateSubShares(participantID int, share *QTDShare, newParticipantIDs []int, newThreshold int) ([]*SubShare, error) {
	if share == nil || len(newParticipantIDs) == 0 || newThreshold <= 0 {
		return nil, ErrInvalidConfig
	}

	s1Vec, err := VecFromBytes(share.S1ShareBytes, Dilithium3L)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize s1: %w", err)
	}
	s2Vec, err := VecFromBytes(share.S2ShareBytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize s2: %w", err)
	}
	t0Vec, err := VecFromBytes(share.T0ShareBytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize t0: %w", err)
	}

	s1SubShares, err := generateSubSharesForVec(s1Vec, participantID, newParticipantIDs, newThreshold)
	if err != nil {
		return nil, fmt.Errorf("s1 sub-share generation failed: %w", err)
	}
	s2SubShares, err := generateSubSharesForVec(s2Vec, participantID, newParticipantIDs, newThreshold)
	if err != nil {
		return nil, fmt.Errorf("s2 sub-share generation failed: %w", err)
	}
	t0SubShares, err := generateSubSharesForVec(t0Vec, participantID, newParticipantIDs, newThreshold)
	if err != nil {
		return nil, fmt.Errorf("t0 sub-share generation failed: %w", err)
	}

	result := make([]*SubShare, len(newParticipantIDs))
	for i, newID := range newParticipantIDs {
		result[i] = &SubShare{
			FromParticipant: participantID,
			ToParticipant:   newID,
			S1SubShare:      s1SubShares[newID],
			S2SubShare:      s2SubShares[newID],
			T0SubShare:      t0SubShares[newID],
		}
	}

	return result, nil
}

func generateSubSharesForVec(vec PolyVec, participantID int, newParticipantIDs []int, newThreshold int) (map[int][]byte, error) {
	subVecs, err := shamirSplitPolyVec(vec, newThreshold, len(newParticipantIDs))
	if err != nil {
		return nil, err
	}

	result := make(map[int][]byte, len(newParticipantIDs))
	for i, newID := range newParticipantIDs {
		result[newID] = VecToBytes(subVecs[i+1])
	}

	return result, nil
}

func CombineSubShares(
	allSubShares [][]*SubShare,
	newParticipantIDs []int,
	newThreshold int,
	oldParticipantIDs []int,
	publicKey *QTDPublicKey,
) (*ReshareResult, error) {
	if len(allSubShares) == 0 || len(newParticipantIDs) == 0 {
		return nil, ErrInvalidConfig
	}

	if len(oldParticipantIDs) < newThreshold {
		return nil, fmt.Errorf("%w: need at least %d old participants, got %d", ErrInsufficientParticipants, newThreshold, len(oldParticipantIDs))
	}

	lagrangeCoeffs := make(map[int]int64, len(oldParticipantIDs))
	for _, id := range oldParticipantIDs {
		lagrangeCoeffs[id] = lagrangeCoeff(id, oldParticipantIDs)
	}

	newShares := make([]*QTDShare, len(newParticipantIDs))

	for idx, newID := range newParticipantIDs {
		s1Accum := make(PolyVec, Dilithium3L)
		s2Accum := make(PolyVec, Dilithium3K)
		t0Accum := make(PolyVec, Dilithium3K)

		for _, fromID := range oldParticipantIDs {
			var subShare *SubShare
			for _, batch := range allSubShares {
				for _, ss := range batch {
					if ss.FromParticipant == fromID && ss.ToParticipant == newID {
						subShare = ss
						break
					}
				}
				if subShare != nil {
					break
				}
			}
			if subShare == nil {
				return nil, fmt.Errorf("%w: missing sub-share from %d to %d", ErrParticipantNotFound, fromID, newID)
			}

			coeff := lagrangeCoeffs[fromID]

			s1SubVec, err := VecFromBytes(subShare.S1SubShare, Dilithium3L)
			if err != nil {
				return nil, fmt.Errorf("s1 sub-share deserialize failed: %w", err)
			}
			s2SubVec, err := VecFromBytes(subShare.S2SubShare, Dilithium3K)
			if err != nil {
				return nil, fmt.Errorf("s2 sub-share deserialize failed: %w", err)
			}
			t0SubVec, err := VecFromBytes(subShare.T0SubShare, Dilithium3K)
			if err != nil {
				return nil, fmt.Errorf("t0 sub-share deserialize failed: %w", err)
			}

			s1Weighted := VecScalarMul(s1SubVec, coeff)
			s2Weighted := VecScalarMul(s2SubVec, coeff)
			t0Weighted := VecScalarMul(t0SubVec, coeff)

			s1Accum = VecAdd(s1Accum, s1Weighted)
			s2Accum = VecAdd(s2Accum, s2Weighted)
			t0Accum = VecAdd(t0Accum, t0Weighted)
		}

		newShare := &QTDShare{
			ParticipantID: newID,
			S1ShareBytes:  VecToBytes(s1Accum),
			S2ShareBytes:  VecToBytes(s2Accum),
			T0ShareBytes:  VecToBytes(t0Accum),
		}

		if publicKey != nil {
			newShare.Rho = make([]byte, len(publicKey.Rho))
			copy(newShare.Rho, publicKey.Rho)
			newShare.T1Bytes = make([]byte, len(publicKey.T1))
			copy(newShare.T1Bytes, publicKey.T1)
		}

		vVector, err := generateVerificationVector(newShare.S1ShareBytes, newThreshold)
		if err != nil {
			return nil, fmt.Errorf("verification vector generation failed: %w", err)
		}
		newShare.VVector = vVector

		vVectorS2, errS2 := generateVerificationVector(newShare.S2ShareBytes, newThreshold)
		if errS2 != nil {
			return nil, fmt.Errorf("failed to generate S2 verification vector: %w", errS2)
		}
		newShare.VVectorS2 = vVectorS2

		vVectorT0, errT0 := generateVerificationVector(newShare.T0ShareBytes, newThreshold)
		if errT0 != nil {
			return nil, fmt.Errorf("failed to generate T0 verification vector: %w", errT0)
		}
		newShare.VVectorT0 = vVectorT0

		newShares[idx] = newShare
	}

	return &ReshareResult{
		NewShares:         newShares,
		NewThreshold:      newThreshold,
		NewTotal:          len(newParticipantIDs),
		NewParticipantIDs: newParticipantIDs,
	}, nil
}

func AddParticipant(
	existingShares []*QTDShare,
	newParticipantID int,
	threshold int,
	publicKey *QTDPublicKey,
) ([]*QTDShare, error) {
	if len(existingShares) < threshold {
		return nil, fmt.Errorf("%w: need at least %d existing shares", ErrInsufficientParticipants, threshold)
	}

	oldIDs := make([]int, len(existingShares))
	for i, s := range existingShares {
		oldIDs[i] = s.ParticipantID
	}

	newIDs := make([]int, 0, len(oldIDs)+1)
	newIDs = append(newIDs, oldIDs...)
	newIDs = append(newIDs, newParticipantID)

	allSubShares := make([][]*SubShare, len(existingShares))
	for i, share := range existingShares {
		subShares, err := GenerateSubShares(share.ParticipantID, share, newIDs, threshold)
		if err != nil {
			return nil, fmt.Errorf("sub-share generation failed for participant %d: %w", share.ParticipantID, err)
		}
		allSubShares[i] = subShares
	}

	result, err := CombineSubShares(allSubShares, newIDs, threshold, oldIDs, publicKey)
	if err != nil {
		return nil, fmt.Errorf("sub-share combination failed: %w", err)
	}

	return result.NewShares, nil
}

func RemoveParticipant(
	existingShares []*QTDShare,
	removeParticipantID int,
	threshold int,
	publicKey *QTDPublicKey,
) ([]*QTDShare, error) {
	if len(existingShares)-1 < threshold {
		return nil, fmt.Errorf("%w: removing participant would drop below threshold %d", ErrCannotRemoveShare, threshold)
	}

	remainingShares := make([]*QTDShare, 0, len(existingShares)-1)
	for _, s := range existingShares {
		if s.ParticipantID != removeParticipantID {
			remainingShares = append(remainingShares, s)
		}
	}

	if len(remainingShares) < threshold {
		return nil, ErrCannotRemoveShare
	}

	oldIDs := make([]int, len(remainingShares))
	for i, s := range remainingShares {
		oldIDs[i] = s.ParticipantID
	}

	newIDs := make([]int, len(oldIDs))
	copy(newIDs, oldIDs)

	allSubShares := make([][]*SubShare, len(remainingShares))
	for i, share := range remainingShares {
		subShares, err := GenerateSubShares(share.ParticipantID, share, newIDs, threshold)
		if err != nil {
			return nil, fmt.Errorf("sub-share generation failed for participant %d: %w", share.ParticipantID, err)
		}
		allSubShares[i] = subShares
	}

	result, err := CombineSubShares(allSubShares, newIDs, threshold, oldIDs, publicKey)
	if err != nil {
		return nil, fmt.Errorf("sub-share combination failed: %w", err)
	}

	return result.NewShares, nil
}

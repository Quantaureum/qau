// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"testing"
)

func TestRefreshDeltas_ZeroSum(t *testing.T) {
	ids := []int{1, 2, 3}
	deltas, err := GenerateRefreshDeltas(1, ids, Dilithium3L, Dilithium3K, Dilithium3K)
	if err != nil {
		t.Fatalf("GenerateRefreshDeltas failed: %v", err)
	}

	s1Sum := make(PolyVec, Dilithium3L)
	s2Sum := make(PolyVec, Dilithium3K)
	t0Sum := make(PolyVec, Dilithium3K)

	for _, id := range ids {
		s1Sum = VecAdd(s1Sum, deltas.S1Deltas[id])
		s2Sum = VecAdd(s2Sum, deltas.S2Deltas[id])
		t0Sum = VecAdd(t0Sum, deltas.T0Deltas[id])
	}

	if VecNormInf(s1Sum) != 0 {
		t.Fatalf("s1 deltas do not sum to zero: norm=%d", VecNormInf(s1Sum))
	}
	if VecNormInf(s2Sum) != 0 {
		t.Fatalf("s2 deltas do not sum to zero: norm=%d", VecNormInf(s2Sum))
	}
	if VecNormInf(t0Sum) != 0 {
		t.Fatalf("t0 deltas do not sum to zero: norm=%d", VecNormInf(t0Sum))
	}
}

func TestRefreshDeltas_CommitmentVerification(t *testing.T) {
	ids := []int{1, 2, 3}
	deltas, err := GenerateRefreshDeltas(1, ids, Dilithium3L, Dilithium3K, Dilithium3K)
	if err != nil {
		t.Fatalf("GenerateRefreshDeltas failed: %v", err)
	}

	if !VerifyRefreshCommitment(deltas) {
		t.Fatal("commitment verification failed for valid deltas")
	}

	deltas.S1Deltas[1][0][0] = (deltas.S1Deltas[1][0][0] + 1) % Q
	if VerifyRefreshCommitment(deltas) {
		t.Fatal("commitment verification should fail for tampered deltas")
	}
}

func TestRefreshDeltas_AllParticipants(t *testing.T) {
	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, len(ids))
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed for %d: %v", id, err)
		}
		allDeltas[i] = d
	}

	totalS1Delta := make(PolyVec, Dilithium3L)
	totalS2Delta := make(PolyVec, Dilithium3K)
	totalT0Delta := make(PolyVec, Dilithium3K)

	for _, d := range allDeltas {
		for _, id := range ids {
			totalS1Delta = VecAdd(totalS1Delta, d.S1Deltas[id])
			totalS2Delta = VecAdd(totalS2Delta, d.S2Deltas[id])
			totalT0Delta = VecAdd(totalT0Delta, d.T0Deltas[id])
		}
	}

	if VecNormInf(totalS1Delta) != 0 {
		t.Fatalf("total s1 deltas across all participants do not sum to zero: norm=%d", VecNormInf(totalS1Delta))
	}
	if VecNormInf(totalS2Delta) != 0 {
		t.Fatalf("total s2 deltas across all participants do not sum to zero: norm=%d", VecNormInf(totalS2Delta))
	}
	if VecNormInf(totalT0Delta) != 0 {
		t.Fatalf("total t0 deltas across all participants do not sum to zero: norm=%d", VecNormInf(totalT0Delta))
	}
}

func TestRefreshShares_Additive(t *testing.T) {
	pubKey, shares, err := GenerateDKGShares(3, 3)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, 3)
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed: %v", err)
		}
		allDeltas[i] = d
	}

	updatedShares, err := ApplyRefreshDeltas(shares, allDeltas)
	if err != nil {
		t.Fatalf("ApplyRefreshDeltas failed: %v", err)
	}

	if err := VerifySecretPreservation(shares, updatedShares); err != nil {
		t.Fatalf("secret not preserved: %v", err)
	}

	if err := VerifyRefreshIntegrity(shares, updatedShares); err != nil {
		t.Fatalf("refresh integrity check failed: %v", err)
	}

	_ = pubKey
}

func TestRefreshShares_Shamir(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, 3)
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed: %v", err)
		}
		allDeltas[i] = d
	}

	updatedShares, err := ApplyRefreshDeltas(shares, allDeltas)
	if err != nil {
		t.Fatalf("ApplyRefreshDeltas failed: %v", err)
	}

	if err := VerifySecretPreservation(shares, updatedShares); err != nil {
		t.Fatalf("secret not preserved: %v", err)
	}

	_ = pubKey
}

func TestRefreshShares_SigningAfterRefresh(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	mgr, err := NewQTDManager(2, 3)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}
	mgr.SetShamirMode(true)
	mgr.SetPublicKey(pubKey)
	for _, s := range shares {
		if err := mgr.AddShare(s); err != nil {
			t.Fatalf("AddShare failed: %v", err)
		}
	}

	msg := []byte("test-before-refresh")
	sig1, err := mgr.CreateSigningSession(msg, []int{1, 2})
	if err != nil {
		t.Fatalf("signing session before refresh failed: %v", err)
	}
	if sig1 == nil {
		t.Fatal("signing session before refresh returned nil")
	}

	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, 3)
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed: %v", err)
		}
		allDeltas[i] = d
	}

	updatedShares, err := ApplyRefreshDeltas(shares, allDeltas)
	if err != nil {
		t.Fatalf("ApplyRefreshDeltas failed: %v", err)
	}

	mgr2, err := NewQTDManager(2, 3)
	if err != nil {
		t.Fatalf("NewQTDManager 2 failed: %v", err)
	}
	mgr2.SetShamirMode(true)
	mgr2.SetPublicKey(pubKey)
	for _, s := range updatedShares {
		if err := mgr2.AddShare(s); err != nil {
			t.Fatalf("AddShare after refresh failed: %v", err)
		}
	}

	msg2 := []byte("test-after-refresh")
	sig2, err := mgr2.CreateSigningSession(msg2, []int{1, 3})
	if err != nil {
		t.Fatalf("signing session after refresh failed: %v", err)
	}
	if sig2 == nil {
		t.Fatal("signing session after refresh returned nil")
	}
}

func TestRefreshShares_MultipleRounds(t *testing.T) {
	_, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	ids := []int{1, 2, 3}
	currentShares := shares

	for round := 0; round < 3; round++ {
		allDeltas := make([]*RefreshDeltas, 3)
		for i, id := range ids {
			d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
			if err != nil {
				t.Fatalf("round %d: GenerateRefreshDeltas failed: %v", round, err)
			}
			allDeltas[i] = d
		}

		updatedShares, err := ApplyRefreshDeltas(currentShares, allDeltas)
		if err != nil {
			t.Fatalf("round %d: ApplyRefreshDeltas failed: %v", round, err)
		}

		if err := VerifySecretPreservation(shares, updatedShares); err != nil {
			t.Fatalf("round %d: secret not preserved from original: %v", round, err)
		}

		currentShares = updatedShares
	}
}

func TestAddParticipant_Shamir(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	newShares, err := AddParticipant(shares, 4, 2, pubKey)
	if err != nil {
		t.Fatalf("AddParticipant failed: %v", err)
	}

	if len(newShares) != 4 {
		t.Fatalf("expected 4 shares, got %d", len(newShares))
	}

	found := make(map[int]bool)
	for _, s := range newShares {
		found[s.ParticipantID] = true
	}
	for _, id := range []int{1, 2, 3, 4} {
		if !found[id] {
			t.Fatalf("participant %d not found in new shares", id)
		}
	}
}

func TestAddParticipant_SigningAfterAdd(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	newShares, err := AddParticipant(shares, 4, 2, pubKey)
	if err != nil {
		t.Fatalf("AddParticipant failed: %v", err)
	}

	mgr, err := NewQTDManager(2, 4)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}
	mgr.SetShamirMode(true)
	mgr.SetPublicKey(pubKey)
	for _, s := range newShares {
		if err := mgr.AddShare(s); err != nil {
			t.Fatalf("AddShare failed for %d: %v", s.ParticipantID, err)
		}
	}

	msg := []byte("test-after-add-participant")
	session, err := mgr.CreateSigningSession(msg, []int{2, 4})
	if err != nil {
		t.Fatalf("signing session with new participant failed: %v", err)
	}
	if session == nil {
		t.Fatal("signing session returned nil")
	}
}

func TestAddParticipant_InsufficientShares(t *testing.T) {
	_, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	_, err = AddParticipant(shares[:1], 4, 2, nil)
	if err == nil {
		t.Fatal("expected error with insufficient shares")
	}
}

func TestRemoveParticipant_Shamir(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	newShares, err := RemoveParticipant(shares, 3, 2, pubKey)
	if err != nil {
		t.Fatalf("RemoveParticipant failed: %v", err)
	}

	if len(newShares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(newShares))
	}

	for _, s := range newShares {
		if s.ParticipantID == 3 {
			t.Fatal("participant 3 should have been removed")
		}
	}
}

func TestRemoveParticipant_BelowThreshold(t *testing.T) {
	_, shares, err := GenerateDKGShares(3, 3)
	if err != nil {
		t.Fatalf("Additive DKG failed: %v", err)
	}

	_, err = RemoveParticipant(shares, 1, 3, nil)
	if err == nil {
		t.Fatal("expected error when removal would drop below threshold")
	}
}

func TestRemoveParticipant_SigningAfterRemove(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 4)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	newShares, err := RemoveParticipant(shares, 4, 2, pubKey)
	if err != nil {
		t.Fatalf("RemoveParticipant failed: %v", err)
	}

	mgr, err := NewQTDManager(2, 3)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}
	mgr.SetShamirMode(true)
	mgr.SetPublicKey(pubKey)
	for _, s := range newShares {
		if err := mgr.AddShare(s); err != nil {
			t.Fatalf("AddShare failed for %d: %v", s.ParticipantID, err)
		}
	}

	msg := []byte("test-after-remove-participant")
	session, err := mgr.CreateSigningSession(msg, []int{1, 2})
	if err != nil {
		t.Fatalf("signing session after remove failed: %v", err)
	}
	if session == nil {
		t.Fatal("signing session returned nil")
	}
}

func TestRefreshAndReshare_Combined(t *testing.T) {
	pubKey, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, 3)
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed: %v", err)
		}
		allDeltas[i] = d
	}

	refreshedShares, err := ApplyRefreshDeltas(shares, allDeltas)
	if err != nil {
		t.Fatalf("ApplyRefreshDeltas failed: %v", err)
	}

	if err := VerifySecretPreservation(shares, refreshedShares); err != nil {
		t.Fatalf("secret not preserved after refresh: %v", err)
	}

	expandedShares, err := AddParticipant(refreshedShares, 4, 2, pubKey)
	if err != nil {
		t.Fatalf("AddParticipant after refresh failed: %v", err)
	}

	if len(expandedShares) != 4 {
		t.Fatalf("expected 4 shares after add, got %d", len(expandedShares))
	}

	reducedShares, err := RemoveParticipant(expandedShares, 4, 2, pubKey)
	if err != nil {
		t.Fatalf("RemoveParticipant after add failed: %v", err)
	}

	if len(reducedShares) != 3 {
		t.Fatalf("expected 3 shares after remove, got %d", len(reducedShares))
	}
}

func TestRefreshDeltas_DeterministicCommitment(t *testing.T) {
	ids := []int{1, 2, 3}
	d1, err := GenerateRefreshDeltas(1, ids, Dilithium3L, Dilithium3K, Dilithium3K)
	if err != nil {
		t.Fatalf("GenerateRefreshDeltas failed: %v", err)
	}

	computed := ComputeRefreshCommitment(d1)
	if len(computed) != 32 {
		t.Fatalf("expected 32-byte commitment, got %d", len(computed))
	}

	computed2 := ComputeRefreshCommitment(d1)
	for i := range computed {
		if computed[i] != computed2[i] {
			t.Fatal("commitment is not deterministic")
		}
	}
}

func TestRefreshShares_OldSharesInvalidated(t *testing.T) {
	_, shares, err := GenerateDKGSharesShamir(2, 3)
	if err != nil {
		t.Fatalf("Shamir DKG failed: %v", err)
	}

	ids := []int{1, 2, 3}
	allDeltas := make([]*RefreshDeltas, 3)
	for i, id := range ids {
		d, err := GenerateRefreshDeltas(id, ids, Dilithium3L, Dilithium3K, Dilithium3K)
		if err != nil {
			t.Fatalf("GenerateRefreshDeltas failed: %v", err)
		}
		allDeltas[i] = d
	}

	updatedShares, err := ApplyRefreshDeltas(shares, allDeltas)
	if err != nil {
		t.Fatalf("ApplyRefreshDeltas failed: %v", err)
	}

	for i := range shares {
		sameS1 := true
		for j := range shares[i].S1ShareBytes {
			if shares[i].S1ShareBytes[j] != updatedShares[i].S1ShareBytes[j] {
				sameS1 = false
				break
			}
		}
		if sameS1 {
			t.Fatalf("participant %d: s1 share unchanged after refresh", shares[i].ParticipantID)
		}
	}
}

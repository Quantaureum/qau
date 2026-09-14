// Quantaureum Node source, version 1.0.0.
package core

import (
	"sync"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// ─── R37-P3-32 regression tests ───
//
// AUDIT (2026) R37-P3-32 (LOW): The DA sampling cache key in
// DankshardingEngine.VerifyBlockDAAvailability is (slot, commitmentsHash),
// while the DASClient session map (encoding/das.go) is keyed by slot only.
// The key-dimension mismatch allowed:
//   1. Cache pollution: two different commitment sets for the same slot
//      overwrote each other's DAS session mid-sampling (no serialization).
//   2. Wrong attestation stats: BuildDAAttestation read SampleCount/
//      SuccessCount via GetSession(slot) — the slot-only session may belong
//      to a DIFFERENT commitment set than the one just verified.
//
// FIX (2026-07-31): sampleSessionMu serializes NewSession+Sample+stats read;
// sample counters are captured into the (slot, commitmentsHash)-keyed cache
// entry and BuildDAAttestation reads them from that entry.

// r37p32NewEngine builds a minimal DA engine whose cell getter serves
// honest proofs for the CURRENT DAS session commitments, except when the
// session holds badCommitments — then it returns invalid proofs (simulating
// a fork blob set whose data this node does not have).
func r37p32NewEngine(t *testing.T, badCommitments []encoding.KZGCommitment) *DankshardingEngine {
	t.Helper()
	engine := r5DA02NewEngine(t)
	engine.dasClient.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*encoding.DASSampleResponse, error) {
		session := engine.dasClient.GetSession(slot)
		if session == nil || blobIndex < 0 || blobIndex >= len(session.Commitments) {
			return nil, nil
		}
		commitment := session.Commitments[blobIndex]
		var cell encoding.Cell
		cell[0] = byte(row) ^ byte(col) ^ 0x5A
		proof, _ := encoding.ComputeCellProof(cell, row, col, commitment)
		if commitment == badCommitments[blobIndex%len(badCommitments)] {
			proof = encoding.KZGProof{} // invalid proof → verification failure
		}
		return &encoding.DASSampleResponse{
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      cell,
			Proof:     proof,
		}, nil
	})
	return engine
}

// TestR37_P3_32_AttestationStatsKeyedByCommitments verifies that
// BuildDAAttestation's SampleCount/SuccessCount come from the cache entry
// for the SAME (slot, commitmentsHash) — not from whichever commitment set
// most recently overwrote the slot-only DAS session.
func TestR37_P3_32_AttestationStatsKeyedByCommitments(t *testing.T) {
	commitmentsA := []encoding.KZGCommitment{{0xAA}} // node HAS this data
	commitmentsB := []encoding.KZGCommitment{{0xBB}} // node does NOT (bad proofs)
	engine := r37p32NewEngine(t, commitmentsB)

	const slot = 1
	// Sample set A: all proofs valid → success == total > 0.
	attA, err := engine.BuildDAAttestation(slot, 1, commitmentsA, 0)
	if err != nil {
		t.Fatalf("BuildDAAttestation(A) failed: %v", err)
	}
	if !attA.Available {
		t.Error("expected attestation A available=true (valid proofs)")
	}
	if attA.SampleCount == 0 || attA.SuccessCount != attA.SampleCount {
		t.Errorf("attestation A stats wrong: total=%d success=%d, want success==total>0",
			attA.SampleCount, attA.SuccessCount)
	}

	// Sample set B for the SAME slot: overwrites the slot-only DAS session.
	// All proofs invalid → success == 0, available == false.
	attB, err := engine.BuildDAAttestation(slot, 1, commitmentsB, 0)
	if err != nil {
		t.Fatalf("BuildDAAttestation(B) failed: %v", err)
	}
	if attB.Available {
		t.Error("expected attestation B available=false (invalid proofs)")
	}
	if attB.SuccessCount != 0 {
		t.Errorf("attestation B stats wrong: success=%d, want 0", attB.SuccessCount)
	}

	// R37-P3-32 core assertion: re-building A's attestation AFTER B's
	// session overwrote the slot must still report A's stats. Pre-fix this
	// read GetSession(slot) → B's session → SuccessCount==0 (polluted).
	attA2, err := engine.BuildDAAttestation(slot, 1, commitmentsA, 0)
	if err != nil {
		t.Fatalf("BuildDAAttestation(A, second) failed: %v", err)
	}
	if attA2.SuccessCount != attA.SuccessCount || attA2.SampleCount != attA.SampleCount {
		t.Errorf("R37-P3-32: attestation A stats polluted by set B session: "+
			"first(total=%d success=%d) second(total=%d success=%d)",
			attA.SampleCount, attA.SuccessCount, attA2.SampleCount, attA2.SuccessCount)
	}
	if !attA2.Available {
		t.Error("R37-P3-32: cached result for A must remain available=true")
	}
}

// TestR37_P3_32_ConcurrentForkSamplingNoPollution hammers the same slot
// with two different commitment sets concurrently (fresh slot per round so
// each round exercises a real sampling, not a cache hit). Set A must ALWAYS
// sample available=true and set B always available=false. Pre-fix, an
// interleaved NewSession could make A sample against B's session (or vice
// versa), flipping the cached availability.
func TestR37_P3_32_ConcurrentForkSamplingNoPollution(t *testing.T) {
	commitmentsA := []encoding.KZGCommitment{{0xAA}}
	commitmentsB := []encoding.KZGCommitment{{0xBB}}
	engine := r37p32NewEngine(t, commitmentsB)

	const rounds = 5
	for round := 0; round < rounds; round++ {
		slot := uint64(100 + round)
		var wg sync.WaitGroup
		var availA, availB bool
		var errA, errB error
		wg.Add(2)
		go func() {
			defer wg.Done()
			availA, _, errA = engine.VerifyBlockDAAvailability(slot, 1, commitmentsA)
		}()
		go func() {
			defer wg.Done()
			availB, _, errB = engine.VerifyBlockDAAvailability(slot, 1, commitmentsB)
		}()
		wg.Wait()
		if errA != nil {
			t.Fatalf("slot %d: VerifyBlockDAAvailability(A) error: %v", slot, errA)
		}
		if errB != nil {
			t.Fatalf("slot %d: VerifyBlockDAAvailability(B) error: %v", slot, errB)
		}
		if !availA {
			t.Errorf("slot %d: R37-P3-32 pollution: set A sampled unavailable", slot)
		}
		if availB {
			t.Errorf("slot %d: R37-P3-32 pollution: set B sampled available", slot)
		}
	}
}

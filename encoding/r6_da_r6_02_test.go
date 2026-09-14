// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── DA: DASAttestation.Hash() binds all commitments closure test ──
//
// Audit quote (AUDIT-FULL-ROUND6-2026-07-17.md DA):
//   DASAttestation.Hash() bound only commitment 0. Hash() must bind all commitments.
//
// Fix status: fixed (2026-07-16). Hash() now includes the complete
// BlobCommitments slice (length prefix + each commitment), preventing cross-commitment-set reuse.
//
// This file explicitly verifies closure.

// TestDA_R6_02_HashBindsAllCommitments verifies that Hash() binds the FULL
// BlobCommitments set, not just BlobCommitment (commitments[0]).
func TestDA_R6_02_HashBindsAllCommitments(t *testing.T) {
	// Two commitment sets sharing [0] but differing in [1] and [2].
	// DA- (2026-07-17): KZGCommitment is 48 bytes; only first byte is set.
	setA := []KZGCommitment{{0xAA}, {0x11}, {0x22}}
	setB := []KZGCommitment{{0xAA}, {0x33}, {0x44}}

	attA := baseAttestationDA_R5_04(setA)
	attB := baseAttestationDA_R5_04(setB)

	hashA := attA.Hash()
	hashB := attB.Hash()

	if hashA == hashB {
		t.Fatal(" NOT FIXED: Two attestations with same commitments[0] but different [1..] produced same hash")
	}
	t.Logf("SUCCESS: Different commitment sets produce different hashes (FIXED)")
	t.Logf("  hashA: %x", hashA[:8])
	t.Logf("  hashB: %x", hashB[:8])
}

// TestDA_R6_02_LegacyFieldAloneInsufficient verifies that the legacy
// BlobCommitment field alone (without BlobCommitments slice) does NOT
// produce the same hash as an attestation with the full set.
func TestDA_R6_02_LegacyFieldAloneInsufficient(t *testing.T) {
	// Legacy attestation: only BlobCommitment set, BlobCommitments empty.
	legacy := &DASAttestation{
		Slot:            42,
		BlobCommitment:  types.Hash{0xAA},
		Available:       true,
		Confidence:      0.99,
		SampleCount:     50,
		SuccessCount:    50,
		ValidatorIndex:  1,
		Signature:       []byte{0xDE, 0xAD},
		BlobCommitments: nil, // empty — legacy mode
	}

	// Modern attestation: BlobCommitment + full BlobCommitments set.
	modern := baseAttestationDA_R5_04([]KZGCommitment{{0xAA}, {0xBB}})

	hashLegacy := legacy.Hash()
	hashModern := modern.Hash()

	if hashLegacy == hashModern {
		t.Fatal(" NOT FIXED: Legacy attestation (no BlobCommitments) has same hash as modern attestation with full set")
	}
	t.Logf("SUCCESS: Legacy and modern attestations produce different hashes")
}

// TestDA_R6_02_CommitmentCountAffectsHash verifies that the commitment COUNT
// affects the hash (length-prefix binding). Two attestations with the same
// commitments but different counts must produce different hashes.
func TestDA_R6_02_CommitmentCountAffectsHash(t *testing.T) {
	// setA has 2 commitments, setB has 3 (first 2 identical).
	setA := []KZGCommitment{{0xAA}, {0xBB}}
	setB := []KZGCommitment{{0xAA}, {0xBB}, {0xCC}}

	attA := baseAttestationDA_R5_04(setA)
	attB := baseAttestationDA_R5_04(setB)

	hashA := attA.Hash()
	hashB := attB.Hash()

	if hashA == hashB {
		t.Fatal(" NOT FIXED: Different commitment counts produce same hash (length-prefix missing)")
	}
	t.Logf("SUCCESS: Commitment count affects hash (length-prefix binding works)")
}

// TestDA_R6_02_SingleCommitmentSetConsistent verifies that the same
// commitment set produces the same hash across multiple calls (determinism).
func TestDA_R6_02_SingleCommitmentSetConsistent(t *testing.T) {
	set := []KZGCommitment{{0x01}, {0x02}, {0x03}}
	att := baseAttestationDA_R5_04(set)

	hash1 := att.Hash()
	hash2 := att.Hash()

	if hash1 != hash2 {
		t.Fatal(" Same attestation produced different hashes — non-deterministic")
	}
	t.Logf("SUCCESS: Hash is deterministic for the same commitment set")
}

// TestDA_R6_02_FixedSummary documents the  closure status.
func TestDA_R6_02_FixedSummary(t *testing.T) {
	t.Log("=== DA- CLOSURE SUMMARY ===")
	t.Log("")
	t.Log("Audit finding (R6): DASAttestation.Hash() only bound commitments[0].")
	t.Log("")
	t.Log("Fix (DA-, 2026-07-16): Hash() now includes the FULL BlobCommitments")
	t.Log("slice with length-prefix: keccak256(slot || commitments[0] || ... ||")
	t.Log("available || confidence || sampleCount || successCount || validatorIdx ||")
	t.Log("len(commitments) || commitments[0] || commitments[1] || ...)")
	t.Log("")
	t.Log("Security properties:")
	t.Log("  1. Full binding: hash covers every commitment in the set.")
	t.Log("  2. Length-prefix: commitment count is bound (prevents truncation attacks).")
	t.Log("  3. Cross-set reuse prevented: two sets sharing [0] but differing in [1..]")
	t.Log("     produce different hashes.")
	t.Log("  4. Backward compat: legacy attestations (empty BlobCommitments) still hash.")
	t.Log("")
	t.Log(" status: FIXED (via DA-) ✓")
}

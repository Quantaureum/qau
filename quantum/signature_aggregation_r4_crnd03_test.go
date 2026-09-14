// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"testing"

	qaucrypto "github.com/quantaureum/qau/crypto"
)

// TestR4CRND03_VerifyAggregation_RejectsDuplicatePublicKeys verifies that
// VerifyAggregation rejects aggregates that contain duplicate public keys.
// AUDIT (2026) R4-CRND-03: Without this check, an attacker could submit
// the same (pubKey, sig) pair multiple times to inflate the Count field,
// faking a quorum (e.g., Count=100 with only 1 unique signer).
func TestR4CRND03_VerifyAggregation_RejectsDuplicatePublicKeys(t *testing.T) {
	qsa := NewQuantumSignatureAggregator(2, 10)
	msg := []byte("r4-crnd-03-dup-keys")

	// Generate one real Dilithium3 key pair and one different pair.
	kp1 := getTestPartyKey(0xA1)
	kp2 := getTestPartyKey(0xA2)
	sig1, err := qaucrypto.Sign(kp1.priv, msg)
	if err != nil {
		t.Fatalf("failed to sign with kp1: %v", err)
	}
	sig2, err := qaucrypto.Sign(kp2.priv, msg)
	if err != nil {
		t.Fatalf("failed to sign with kp2: %v", err)
	}

	t.Run("duplicate_public_key_rejected", func(t *testing.T) {
		// Two signatures from the SAME key (kp1) — Count=2 but only 1 unique signer.
		// Construct the aggregate manually to bypass Aggregate()'s own dedup checks
		// (which is the exact path a malicious attacker would take).
		pubKeyBytes := kp1.pub.Bytes()
		agg := &AggregatedSignature{
			Signatures: [][]byte{sig1, sig1},
			PublicKeys: [][]byte{pubKeyBytes, pubKeyBytes},
			Message:    msg,
			Aggregated: qsa.combineSignatures([][]byte{sig1, sig1}),
			Count:      2,
			Threshold:  2,
		}
		if qsa.VerifyAggregation(agg) {
			t.Fatal("R4-CRND-03: VerifyAggregation must reject duplicate public keys " +
				"(Count=2 but only 1 unique signer should not pass quorum)")
		}
	})

	t.Run("unique_public_keys_accepted", func(t *testing.T) {
		// Non-regression: two distinct keys must still verify successfully.
		sigs := [][]byte{sig1, sig2}
		keys := [][]byte{kp1.pub.Bytes(), kp2.pub.Bytes()}
		agg, err := qsa.Aggregate(msg, sigs, keys)
		if err != nil {
			t.Fatalf("Aggregate failed: %v", err)
		}
		if !qsa.VerifyAggregation(agg) {
			t.Fatal("R4-CRND-03 non-regression: VerifyAggregation should accept " +
				"aggregates with unique public keys")
		}
	})

	t.Run("duplicate_among_larger_set_rejected", func(t *testing.T) {
		// 3 entries where one key is duplicated: kp1, kp2, kp1 again.
		// Count=3 but only 2 unique signers — should be rejected.
		pub1 := kp1.pub.Bytes()
		pub2 := kp2.pub.Bytes()
		sigs := [][]byte{sig1, sig2, sig1}
		keys := [][]byte{pub1, pub2, pub1}
		agg := &AggregatedSignature{
			Signatures: sigs,
			PublicKeys: keys,
			Message:    msg,
			Aggregated: qsa.combineSignatures(sigs),
			Count:      3,
			Threshold:  2,
		}
		if qsa.VerifyAggregation(agg) {
			t.Fatal("R4-CRND-03: VerifyAggregation must reject aggregates where " +
				"a public key appears more than once, even when other keys are unique")
		}
	})
}

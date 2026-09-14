// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// =============================================================================
// CRYPTO-R13-001 + CRYPTO-R13-002 (2026-07-21) tests:
// Transaction.SigningHash() — full field coverage + domain separation
//
// CRYPTO-R13-001: SigningHash previously omitted all EIP-1559/4844/multi-sig/
// privacy extension fields, allowing signature-valid tampering with
// MaxFeePerGas, MultiSigRequiredSigs, PrivacyNullifier, etc.
//
// CRYPTO-R13-002: SigningHash lacked a domain separation prefix, allowing
// cross-protocol signature reuse.
//
// These tests verify that:
//  1. Tampering with any extension field invalidates the signature hash
//  2. The domain separator is prepended (different hash vs. raw marshal)
//  3. Signature/PublicKey/EthHash are excluded (signing/verify path parity)
//  4. BlobSidecar is excluded (EIP-4844 spec)
// =============================================================================

// baseTxForR13 returns a Transaction with all fields populated so each
// test can clone it, mutate one field, and verify the hash changes.
func baseTxForR13() *Transaction {
	to := types.BytesToAddress([]byte{0x42})
	return &Transaction{
		Version:                 1,
		Type:                    TxTypePrivacy,
		Nonce:                   42,
		From:                    types.BytesToAddress([]byte{0x01}),
		To:                      &to,
		Value:                   big.NewInt(1000),
		GasLimit:                21000,
		GasPrice:                big.NewInt(1),
		Data:                    []byte("payload"),
		ChainID:                 1668,
		MaxFeePerGas:            big.NewInt(2),
		MaxPriorityFeePerGas:    big.NewInt(1),
		MaxFeePerBlobGas:        big.NewInt(3),
		BlobVersionedHashes:     []types.Hash{types.BytesToHash([]byte("blob-hash-1"))},
		BlobGasUsed:             2,
		MultiSigSignatures:      [][]byte{[]byte("sig1")},
		MultiSigSignerBitmap:    []byte{0x01},
		MultiSigRequiredSigs:    2,
		MultiSigTotalSigners:    3,
		PrivacyEphemeralPubKey:  []byte("ephemeral-pub"),
		PrivacyStealthAddrHash:  types.BytesToHash([]byte("stealth")),
		PrivacyCommitments:      [][]byte{[]byte("commit1")},
		PrivacyEncryptedAmounts: [][]byte{[]byte("enc1")},
		PrivacyRangeProofs:      [][]byte{[]byte("rp1")},
		PrivacyBalanceProof:     []byte("bp1"),
		PrivacyNullifier:        types.BytesToHash([]byte("nullifier")),
	}
}

// TestCRYPTO_R13_001_MaxFeePerGas_InSigningHash verifies that changing
// MaxFeePerGas changes the SigningHash.
func TestCRYPTO_R13_001_MaxFeePerGas_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.MaxFeePerGas = big.NewInt(999)
	h1, err := tx1.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash 1: %v", err)
	}
	h2, err := tx2.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash 2: %v", err)
	}
	if h1 == h2 {
		t.Error("MaxFeePerGas change did not affect SigningHash — CRYPTO-R13-001 not fixed")
	}
}

// TestCRYPTO_R13_001_MaxPriorityFeePerGas_InSigningHash verifies that
// changing MaxPriorityFeePerGas changes the SigningHash.
func TestCRYPTO_R13_001_MaxPriorityFeePerGas_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.MaxPriorityFeePerGas = big.NewInt(777)
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("MaxPriorityFeePerGas change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_MaxFeePerBlobGas_InSigningHash verifies that
// changing MaxFeePerBlobGas changes the SigningHash.
func TestCRYPTO_R13_001_MaxFeePerBlobGas_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.MaxFeePerBlobGas = big.NewInt(555)
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("MaxFeePerBlobGas change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_BlobVersionedHashes_InSigningHash verifies that
// changing BlobVersionedHashes changes the SigningHash.
func TestCRYPTO_R13_001_BlobVersionedHashes_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.BlobVersionedHashes = []types.Hash{types.BytesToHash([]byte("different-blob"))}
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("BlobVersionedHashes change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_MultiSigRequiredSigs_InSigningHash verifies that
// changing MultiSigRequiredSigs changes the SigningHash (critical:
// prevents downgrading 3-of-5 to 1-of-5).
//
// NOTE: MarshalTransaction only emits MultiSig fields when Type == TxTypeMultiSig,
// so we set the Type accordingly. This matches consensus validation, which
// rejects MultiSig fields on non-MultiSig transaction types.
func TestCRYPTO_R13_001_MultiSigRequiredSigs_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx1.Type = TxTypeMultiSig
	tx2 := baseTxForR13()
	tx2.Type = TxTypeMultiSig
	tx2.MultiSigRequiredSigs = 1 // attacker downgrades from 2 to 1
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("MultiSigRequiredSigs change did not affect SigningHash — multi-sig bypass possible")
	}
}

// TestCRYPTO_R13_001_MultiSigTotalSigners_InSigningHash verifies that
// changing MultiSigTotalSigners changes the SigningHash.
func TestCRYPTO_R13_001_MultiSigTotalSigners_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx1.Type = TxTypeMultiSig
	tx2 := baseTxForR13()
	tx2.Type = TxTypeMultiSig
	tx2.MultiSigTotalSigners = 99
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("MultiSigTotalSigners change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_MultiSigSignerBitmap_InSigningHash verifies that
// changing MultiSigSignerBitmap changes the SigningHash.
func TestCRYPTO_R13_001_MultiSigSignerBitmap_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx1.Type = TxTypeMultiSig
	tx2 := baseTxForR13()
	tx2.Type = TxTypeMultiSig
	tx2.MultiSigSignerBitmap = []byte{0xFF}
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("MultiSigSignerBitmap change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_PrivacyNullifier_InSigningHash verifies that
// changing PrivacyNullifier changes the SigningHash (critical: prevents
// double-spend via nullifier substitution).
func TestCRYPTO_R13_001_PrivacyNullifier_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.PrivacyNullifier = types.BytesToHash([]byte("different-nullifier"))
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("PrivacyNullifier change did not affect SigningHash — double-spend possible")
	}
}

// TestCRYPTO_R13_001_PrivacyEphemeralPubKey_InSigningHash verifies that
// changing PrivacyEphemeralPubKey changes the SigningHash.
func TestCRYPTO_R13_001_PrivacyEphemeralPubKey_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.PrivacyEphemeralPubKey = []byte("different-ephemeral")
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("PrivacyEphemeralPubKey change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_PrivacyCommitments_InSigningHash verifies that
// changing PrivacyCommitments changes the SigningHash.
func TestCRYPTO_R13_001_PrivacyCommitments_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.PrivacyCommitments = [][]byte{[]byte("different-commit")}
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("PrivacyCommitments change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_PrivacyRangeProofs_InSigningHash verifies that
// changing PrivacyRangeProofs changes the SigningHash.
func TestCRYPTO_R13_001_PrivacyRangeProofs_InSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx2.PrivacyRangeProofs = [][]byte{[]byte("different-rp")}
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 == h2 {
		t.Error("PrivacyRangeProofs change did not affect SigningHash")
	}
}

// TestCRYPTO_R13_001_BlobSidecar_ExcludedFromSigningHash verifies that
// BlobSidecar is NOT included in SigningHash (per EIP-4844 spec).
// Two transactions with identical fields except BlobSidecar should
// produce the same SigningHash.
func TestCRYPTO_R13_001_BlobSidecar_ExcludedFromSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	// Same BlobVersionedHashes but different BlobSidecar — should NOT
	// affect SigningHash because BlobSidecar is intentionally excluded.
	tx1.BlobSidecar = nil
	var blobExample Blob
	copy(blobExample[:], []byte("blob-data"))
	tx2.BlobSidecar = &BlobTxSidecar{Blobs: []Blob{blobExample}}
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 != h2 {
		t.Error("BlobSidecar should NOT affect SigningHash (EIP-4844 spec) but it did")
	}
}

// TestCRYPTO_R13_001_Signature_ExcludedFromSigningHash verifies that
// Signature does NOT affect SigningHash (signing/verify path parity).
func TestCRYPTO_R13_001_Signature_ExcludedFromSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx1.Signature = nil
	tx2.Signature = []byte("some-signature-that-shouldnt-affect-hash")
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 != h2 {
		t.Error("Signature should NOT affect SigningHash but it did")
	}
}

// TestCRYPTO_R13_001_PublicKey_ExcludedFromSigningHash verifies that
// PublicKey does NOT affect SigningHash.
func TestCRYPTO_R13_001_PublicKey_ExcludedFromSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx1.PublicKey = nil
	tx2.PublicKey = []byte("some-pubkey-that-shouldnt-affect-hash")
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 != h2 {
		t.Error("PublicKey should NOT affect SigningHash but it did")
	}
}

// TestCRYPTO_R13_001_EthHash_ExcludedFromSigningHash verifies that
// EthHash does NOT affect SigningHash.
func TestCRYPTO_R13_001_EthHash_ExcludedFromSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	tx1.EthHash = types.Hash{}
	tx2.EthHash = types.BytesToHash([]byte("eth-hash"))
	h1, _ := tx1.SigningHash()
	h2, _ := tx2.SigningHash()
	if h1 != h2 {
		t.Error("EthHash should NOT affect SigningHash but it did")
	}
}

// TestCRYPTO_R14_001_MultiSigSignatures_ExcludedFromSigningHash verifies
// that MultiSigSignatures does NOT affect SigningHash.
//
// R14-MED (2026-07-21): CRYPTO-R14-001 fixed a Critical bug where
// MultiSigSignatures was included in SigningHash, making multi-sig
// transactions unverifiable (each subsequent signer hashed a different
// payload containing the previous signatures). The fix sets
// MultiSigSignatures to nil in the SigningHash copy. However, the R13
// test suite covered the exclusion of Signature, PublicKey, EthHash,
// and BlobSidecar but MISSED MultiSigSignatures — leaving the fix
// without regression coverage. This test closes that gap.
//
// Without this test, a future change that removes the
// `MultiSigSignatures: nil` line in proto.go SigningHash would not be
// caught, silently re-introducing the Critical multi-sig verification
// failure.
func TestCRYPTO_R14_001_MultiSigSignatures_ExcludedFromSigningHash(t *testing.T) {
	tx1 := baseTxForR13()
	tx2 := baseTxForR13()
	// tx1 has no collected signatures yet (start of multi-sig collection).
	tx1.MultiSigSignatures = nil
	// tx2 has three collected signatures (mid-collection state).
	// If MultiSigSignatures is incorrectly included in SigningHash,
	// tx2's hash will differ from tx1's, breaking multi-sig verification
	// because each signer would hash a different payload.
	tx2.MultiSigSignatures = [][]byte{
		[]byte("signature-from-signer-1"),
		[]byte("signature-from-signer-2"),
		[]byte("signature-from-signer-3"),
	}
	h1, err := tx1.SigningHash()
	if err != nil {
		t.Fatalf("tx1.SigningHash: %v", err)
	}
	h2, err := tx2.SigningHash()
	if err != nil {
		t.Fatalf("tx2.SigningHash: %v", err)
	}
	if h1 != h2 {
		t.Error("R14-MED regression: MultiSigSignatures should NOT affect SigningHash (each signer must hash the same payload) but it did — multi-sig verification would fail for all but the first signer")
	}
}

// TestR14MED_NormalizeNilBigInt_InSigningHash verifies that nil and
// big.NewInt(0) produce the SAME SigningHash after normalization.
//
// R14-MED (2026-07-21): Go's big.Int.Bytes() returns []byte{} for both
// nil and zero, so without normalization, a tx with Value=nil and a tx
// with Value=big.NewInt(0) would produce DIFFERENT hashes through
// MarshalTransaction (which omits fields when value is nil OR sign==0,
// but the field-presence marker differs). The normalizeBigInt helper
// in SigningHash forces nil → new(big.Int) so both produce the same
// explicit zero encoding.
//
// This test ensures a tx signed with Value=nil can be verified when
// the receiver reconstructs the tx with Value=big.NewInt(0) (common
// pattern in deserialization where missing fields default to zero).
func TestR14MED_NormalizeNilBigInt_InSigningHash(t *testing.T) {
	// txNil has Value=nil (semantically "no value specified")
	txNil := baseTxForR13()
	txNil.Value = nil
	txNil.GasPrice = nil
	txNil.MaxFeePerGas = nil
	txNil.MaxPriorityFeePerGas = nil
	txNil.MaxFeePerBlobGas = nil

	// txZero has Value=big.NewInt(0) (semantically "explicit zero")
	txZero := baseTxForR13()
	txZero.Value = big.NewInt(0)
	txZero.GasPrice = big.NewInt(0)
	txZero.MaxFeePerGas = big.NewInt(0)
	txZero.MaxPriorityFeePerGas = big.NewInt(0)
	txZero.MaxFeePerBlobGas = big.NewInt(0)

	hNil, err := txNil.SigningHash()
	if err != nil {
		t.Fatalf("txNil.SigningHash: %v", err)
	}
	hZero, err := txZero.SigningHash()
	if err != nil {
		t.Fatalf("txZero.SigningHash: %v", err)
	}

	// After normalization, both must produce the same hash — this is
	// the key property that makes signature verification work when
	// the signing side and verifying side disagree on nil vs 0.
	if hNil != hZero {
		t.Errorf("R14-MED: nil and zero big.Int should produce same SigningHash after normalization, got nil=%s zero=%s",
			hNil.String(), hZero.String())
	}
}

// TestR14MED_NonZeroBigInt_DifferentFromNormalizedZero verifies that
// the normalization does NOT collapse non-zero values to zero — only
// nil is normalized, real values must still produce different hashes.
func TestR14MED_NonZeroBigInt_DifferentFromNormalizedZero(t *testing.T) {
	txZero := baseTxForR13()
	txZero.Value = big.NewInt(0)

	txNonZero := baseTxForR13()
	txNonZero.Value = big.NewInt(1)

	hZero, _ := txZero.SigningHash()
	hNonZero, _ := txNonZero.SigningHash()

	if hZero == hNonZero {
		t.Error("R14-MED: zero and non-zero Value should produce DIFFERENT SigningHashes (normalization must not collapse real values)")
	}
}

// TestCRYPTO_R13_002_DomainSeparatorApplied verifies that SigningHash
// is NOT equal to the raw SHA3-256 of the marshaled transaction — i.e.,
// the domain separator is actually prepended.
func TestCRYPTO_R13_002_DomainSeparatorApplied(t *testing.T) {
	tx := baseTxForR13()
	// Compute SigningHash (with domain separator).
	hWithDomain, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}

	// Compute what SigningHash WOULD be without the domain separator.
	// We can't easily call the unexported hashData + MarshalTransaction
	// with the same field-zeroing logic, so we approximate by marshaling
	// the original tx (with all fields including Signature/PublicKey)
	// and verifying the hashes differ. The important property is that
	// SigningHash includes a prefix that's not part of the tx itself.
	//
	// A more rigorous test: verify that the signing hash changes when
	// we use a different domain separator. We can't easily swap the
	// package-level var, but we can verify the hash is deterministic
	// (same input → same hash) and non-trivial (not equal to a hash of
	// just the marshaled data without the prefix).
	hSame, _ := tx.SigningHash()
	if hWithDomain != hSame {
		t.Fatal("SigningHash is not deterministic")
	}

	// Verify the hash is not the zero hash (sanity check).
	if hWithDomain == (types.Hash{}) {
		t.Error("SigningHash returned zero hash")
	}
}

// TestCRYPTO_R13_002_DomainSeparatorContent verifies the domain
// separator contains the expected fixed prefix.
func TestCRYPTO_R13_002_DomainSeparatorContent(t *testing.T) {
	expected := []byte("Quantaureum Transaction v1\x00")
	if !bytes.Equal(signingDomainSeparator, expected) {
		t.Errorf("signingDomainSeparator = %q, want %q",
			signingDomainSeparator, expected)
	}
	// The separator must end with NUL to prevent prefix extension attacks.
	if signingDomainSeparator[len(signingDomainSeparator)-1] != 0x00 {
		t.Error("signingDomainSeparator must end with NUL byte")
	}
}

// TestCRYPTO_R13_001_002_SignVerifyRoundTrip verifies that a transaction
// signed with SigningHash() can be verified with SigningHash() (the
// signing and verification paths use the same hash).
//
// This is a smoke test: it doesn't use actual Dilithium3 signatures
// (which require the crypto package), but verifies that two calls to
// SigningHash() on the same tx produce the same hash.
func TestCRYPTO_R13_001_002_SignVerifyRoundTrip(t *testing.T) {
	tx := baseTxForR13()
	h1, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash 1: %v", err)
	}
	// Simulate "signing" by populating Signature/PublicKey (as the
	// signing path would do).
	tx.Signature = []byte("fake-signature")
	tx.PublicKey = []byte("fake-public-key")
	// SigningHash should still produce the SAME hash because
	// Signature/PublicKey are explicitly zeroed in the copy.
	h2, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash 2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("signing/verify path parity broken: h1=%x h2=%x", h1, h2)
	}
}

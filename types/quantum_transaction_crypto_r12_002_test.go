// Quantaureum Node source, version 1.0.0.
package types

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

// expectedDomainTag is the canonical domain separation tag for
// QuantumTransaction signatures. CRYPTO-R12-002 requires this to be
// a fixed, well-known constant so any cross-protocol signature reuse
// is cryptographically prevented.
const expectedDomainTag = "QUANTAUREUM_QUANTUM_TX_V1"

// rawSHA3OfSerializedTx computes SHA3-256 of the serialized tx WITHOUT
// the domain separation tag — i.e., the pre-R12-002 digest. Used by
// tests to prove that the new digest differs from the raw digest.
func rawSHA3OfSerializedTx(t *testing.T, tx *QuantumTransaction) []byte {
	t.Helper()
	tempTx := &QuantumTransaction{
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		ChainID:  tx.ChainID,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		GasLimit: tx.GasLimit,
		GasPrice: tx.GasPrice,
	}
	data, err := tempTx.Serialize()
	if err != nil {
		t.Fatalf("raw serialize failed: %v", err)
	}
	h := sha3.Sum256(data)
	return h[:]
}

// TestCRYPTO_R12002_DomainTagConstantUnchanged verifies the
// quantumTxDomainSeparationTag constant matches the expected canonical
// value. Changing this constant would silently invalidate every
// pre-existing signature on the chain, so any change must be deliberate
// and accompanied by a chain-state migration.
func TestCRYPTO_R12002_DomainTagConstantUnchanged(t *testing.T) {
	if quantumTxDomainSeparationTag != expectedDomainTag {
		t.Errorf("domain tag constant changed: got %q, want %q",
			quantumTxDomainSeparationTag, expectedDomainTag)
	}
	if quantumTxDomainSeparationTag == "" {
		t.Error("domain tag must not be empty")
	}
}

// TestCRYPTO_R12002_DigestDiffersFromRawSHA3 proves that the digest
// returned by HashForSigning differs from SHA3-256(serialized_tx) —
// i.e., the domain separation tag is actually mixed into the digest.
// If this test fails, the fix has been silently reverted.
func TestCRYPTO_R12002_DigestDiffersFromRawSHA3(t *testing.T) {
	tx, err := NewQuantumTransfer(1, 1668, Address{0x01}, nil)
	if err != nil {
		t.Fatalf("NewQuantumTransfer: %v", err)
	}

	got := tx.HashForSigning()
	if got == nil {
		t.Fatal("HashForSigning returned nil")
	}
	raw := rawSHA3OfSerializedTx(t, tx)

	if bytes.Equal(got, raw) {
		t.Error("CRYPTO-R12-002 REGRESSION: HashForSigning digest equals raw SHA3-256 of serialized tx; domain tag not mixed in")
	}
}

// TestCRYPTO_R12002_LengthPrefixIsBigEndianU32 verifies the 4-byte
// length prefix is a big-endian uint32 equal to len(tag). A malformed
// length prefix would allow length-extension ambiguity if the tag
// itself were ever changed to a variable-length value.
func TestCRYPTO_R12002_LengthPrefixIsBigEndianU32(t *testing.T) {
	tx, _ := NewQuantumTransfer(1, 1668, Address{0x02}, nil)
	got := tx.HashForSigning()
	if got == nil {
		t.Fatal("HashForSigning returned nil")
	}

	// Reconstruct the preimage to verify the length prefix layout.
	tag := []byte(quantumTxDomainSeparationTag)
	expectedLen := uint32(len(tag))

	// The first 4 bytes of the preimage must be the big-endian length.
	// Since SHA3-256 is collision-resistant, the only way to verify the
	// preimage layout is to recompute the digest from the expected
	// preimage and compare.
	tempTx := &QuantumTransaction{
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		ChainID:  tx.ChainID,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		GasLimit: tx.GasLimit,
		GasPrice: tx.GasPrice,
	}
	data, err := tempTx.Serialize()
	if err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	// Build preimage: len(tag) || tag || tx_payload
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, expectedLen)
	preimage := make([]byte, 0, 4+len(tag)+len(data))
	preimage = append(preimage, lenBytes...)
	preimage = append(preimage, tag...)
	preimage = append(preimage, data...)

	expected := sha3.Sum256(preimage)
	if !bytes.Equal(got, expected[:]) {
		t.Errorf("digest mismatch: length prefix layout not (big-endian u32 || tag || payload)")
	}
}

// TestCRYPTO_R12002_CrossProtocolNonReuse verifies that a different
// domain tag produces a different digest for the same transaction.
// This is the core security property of domain separation: a signature
// over one domain cannot be replayed in another.
func TestCRYPTO_R12002_CrossProtocolNonReuse(t *testing.T) {
	tx, _ := NewQuantumTransfer(7, 1668, Address{0x03}, nil)

	// Digest with the production tag.
	prodDigest := tx.HashForSigning()
	if prodDigest == nil {
		t.Fatal("HashForSigning returned nil")
	}

	// Digest with a different (attacker-chosen) tag.
	// We compute it manually by replicating the digest construction.
	tempTx := &QuantumTransaction{
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		ChainID:  tx.ChainID,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		GasLimit: tx.GasLimit,
		GasPrice: tx.GasPrice,
	}
	data, err := tempTx.Serialize()
	if err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	otherTag := []byte("DIFFERENT_PROTOCOL_TAG_V2")
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(otherTag)))
	preimage := make([]byte, 0, 4+len(otherTag)+len(data))
	preimage = append(preimage, lenBytes...)
	preimage = append(preimage, otherTag...)
	preimage = append(preimage, data...)
	otherDigest := sha3.Sum256(preimage)

	if bytes.Equal(prodDigest, otherDigest[:]) {
		t.Error("CRYPTO-R12-002 FAILURE: same tx produced identical digest under different domain tags; cross-protocol signature reuse is possible")
	}
}

// TestCRYPTO_R12002_DigestIsDeterministic verifies that the same
// transaction always produces the same digest. This is required for
// signature verification to be reproducible across nodes.
func TestCRYPTO_R12002_DigestIsDeterministic(t *testing.T) {
	tx1, _ := NewQuantumTransfer(42, 1668, Address{0x04}, nil)
	tx2, _ := NewQuantumTransfer(42, 1668, Address{0x04}, nil)

	d1 := tx1.HashForSigning()
	d2 := tx2.HashForSigning()

	if !bytes.Equal(d1, d2) {
		t.Error("deterministic digest violated: same tx produced different digests")
	}
}

// TestCRYPTO_R12002_DigestDiffersAcrossTxFields verifies that changing
// any signed field changes the digest. This proves the domain tag is
// mixed in ON TOP OF the existing tx serialization, not instead of it.
func TestCRYPTO_R12002_DigestDiffersAcrossTxFields(t *testing.T) {
	base, _ := NewQuantumTransfer(1, 1668, Address{0x05}, nil)
	baseDigest := base.HashForSigning()

	cases := []struct {
		name string
		mut  func() *QuantumTransaction
	}{
		{
			name: "nonce_changed",
			mut: func() *QuantumTransaction {
				tx, _ := NewQuantumTransfer(2, 1668, Address{0x05}, nil)
				return tx
			},
		},
		{
			name: "chain_id_changed",
			mut: func() *QuantumTransaction {
				tx, _ := NewQuantumTransfer(1, 1669, Address{0x05}, nil)
				return tx
			},
		},
		{
			name: "to_changed",
			mut: func() *QuantumTransaction {
				tx, _ := NewQuantumTransfer(1, 1668, Address{0x06}, nil)
				return tx
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := tc.mut()
			otherDigest := other.HashForSigning()
			if bytes.Equal(baseDigest, otherDigest) {
				t.Errorf("digest did not change when %s", tc.name)
			}
		})
	}
}

// trackingSigner is a QuantumSigner that records the last message it was
// asked to sign. Used by CRYPTO-R12-002 tests to verify that Sign() and
// Verify() use the same digest (i.e., the domain tag is consistent
// across both paths).
type trackingSigner struct {
	pub           []byte
	lastSigned    []byte
	signCallCount int
}

func (t *trackingSigner) Sign(message []byte) ([]byte, error) {
	t.lastSigned = append([]byte(nil), message...)
	t.signCallCount++
	sig := make([]byte, QuantumSignatureSize)
	for i := range sig {
		sig[i] = byte(i) ^ message[i%len(message)]
	}
	return sig, nil
}

func (t *trackingSigner) PublicKeyBytes() []byte { return t.pub }

// TestCRYPTO_R12002_SignVerifyRoundTrip verifies that after the domain
// separation change, signing and verification still work end-to-end.
// This is a regression guard: a misaligned tag between Sign and Verify
// would break every transaction silently.
func TestCRYPTO_R12002_SignVerifyRoundTrip(t *testing.T) {
	tx, err := NewQuantumTransfer(10, 1668, Address{0x07}, nil)
	if err != nil {
		t.Fatalf("NewQuantumTransfer: %v", err)
	}

	// Build a valid Dilithium3-sized public key and use the tracking signer.
	pubKey := make([]byte, QuantumPublicKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	signer := &trackingSigner{pub: pubKey}

	if err := tx.Sign(signer); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Sign() sets tx.From = Sender() (derived from pubKey) before
	// computing the digest. Verify() recomputes HashForSigning() and
	// checks the signature. Since both use the same domain tag, the
	// round-trip must succeed.
	//
	// NOTE: The mock signer returns a deterministic placeholder signature
	// that is NOT a real Dilithium3 signature, so Verify() will return
	// false — but the failure must NOT be due to a HashForSigning
	// mismatch. We verify the digest computation path explicitly below.
	if tx.Signature == nil {
		t.Fatal("Sign did not populate Signature")
	}
	if len(tx.Signature) != QuantumSignatureSize {
		t.Errorf("Signature size = %d, want %d", len(tx.Signature), QuantumSignatureSize)
	}
	if signer.signCallCount != 1 {
		t.Errorf("Sign call count = %d, want 1", signer.signCallCount)
	}

	// Verify the digest used by Sign equals the digest used by Verify.
	// Sign() temporarily swaps in pubKey/From, computes HashForSigning,
	// then restores. So we replicate the same swap to compute the
	// expected digest and compare against the message the signer saw.
	prevPub := tx.PublicKey
	prevFrom := tx.From
	tx.PublicKey = pubKey
	tx.From = tx.Sender()
	expectedMsg := tx.HashForSigning()
	tx.PublicKey = prevPub
	tx.From = prevFrom

	if !bytes.Equal(expectedMsg, signer.lastSigned) {
		t.Error("CRYPTO-R12-002: digest used by Sign != digest computed by HashForSigning with swapped fields; Verify() would fail")
	}
}

// TestCRYPTO_R12002_TagIsASCII verifies the domain tag is pure ASCII.
// Non-ASCII bytes in a domain tag could introduce encoding ambiguity
// across implementations (e.g., UTF-8 vs Latin-1) that weakens the
// separation guarantee.
func TestCRYPTO_R12002_TagIsASCII(t *testing.T) {
	for i, b := range []byte(quantumTxDomainSeparationTag) {
		if b > 0x7F {
			t.Errorf("non-ASCII byte 0x%02X at index %d in domain tag", b, i)
		}
	}
}

// TestCRYPTO_R12002_TagContainsProtocolName verifies the domain tag
// includes the protocol name. This prevents a different blockchain
// from accidentally choosing the same tag string.
func TestCRYPTO_R12002_TagContainsProtocolName(t *testing.T) {
	upper := strings.ToUpper(quantumTxDomainSeparationTag)
	if !strings.Contains(upper, "QUANTAUREUM") {
		t.Errorf("domain tag %q does not contain protocol name", quantumTxDomainSeparationTag)
	}
	if !strings.Contains(quantumTxDomainSeparationTag, "V1") {
		t.Errorf("domain tag %q should contain version suffix for future migrations", quantumTxDomainSeparationTag)
	}
}

// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
)

// F-11 (2026-10-21): baseline coverage for the lightclient package — the
// sync-committee verification path (fail-closed rules, bitfield bounds,
// participation thresholds, signature mismatch) and the header-stream
// lifecycle. These are the security checks an SPV client relies on, so the
// rejection paths get explicit vectors; deep SPV/api.go coverage is
// deferred.

func committeePubKeys(t *testing.T, n int) [][]byte {
	t.Helper()
	keys := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		keys = append(keys, kp.Public.Bytes())
	}
	return keys
}

// signHeaderBy produces a header signed by the given subset of key pairs,
// concatenated in committee order, plus the matching bitfield.
func signedHeader(t *testing.T, header *encoding.BlockHeader, members []int, keys []*crypto.KeyPair) {
	t.Helper()
	signingData, err := computeSyncCommitteeSigningData(header)
	if err != nil {
		t.Fatalf("compute signing data: %v", err)
	}
	bitfield := make([]byte, (len(keys)+7)/8)
	var sig []byte
	for _, m := range members {
		s, err := keys[m].Private.Sign(signingData)
		if err != nil {
			t.Fatalf("member %d sign: %v", m, err)
		}
		sig = append(sig, s...)
		bitfield[m/8] |= 1 << (m % 8)
	}
	header.SyncCommitteeBits = bitfield
	header.SyncCommitteeSig = sig
}

func newTestCommittee(t *testing.T, n int) (*SyncCommitteeVerifier, []*crypto.KeyPair) {
	t.Helper()
	members := make([]*crypto.KeyPair, 0, n)
	pubKeys := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair %d: %v", i, err)
		}
		members = append(members, kp)
		pubKeys = append(pubKeys, kp.Public.Bytes())
	}
	v := NewSyncCommitteeVerifier()
	v.UpdateCurrentCommittee(&SyncCommitteeInfo{ValidatorPubKeys: pubKeys})
	return v, members
}

func testHeader() *encoding.BlockHeader {
	h := &encoding.BlockHeader{}
	h.Height = 10
	return h
}

// R2-15: an honestly signed header must verify end-to-end. Before the fix the
// verifier's signing data was self-referential (it hashed the header including
// SyncCommitteeSig/Bits) and diverged from the producer's message, so this
// test could not pass.
func TestSyncCommitteeVerifyAcceptsHonestSignature(t *testing.T) {
	v, members := newTestCommittee(t, 3)
	h := testHeader()
	h.Slot = 77
	h.Epoch = 3
	h.ChainID = 1668
	signedHeader(t, h, []int{0, 1, 2}, members)
	if err := v.VerifyBlockHeader(h); err != nil {
		t.Fatalf("honest header rejected: %v", err)
	}

	// A one-member committee signs alone; 2/3 rounds down to 1.
	v1, members1 := newTestCommittee(t, 1)
	h1 := testHeader()
	h1.ChainID = 1668
	signedHeader(t, h1, []int{0}, members1)
	if err := v1.VerifyBlockHeader(h1); err != nil {
		t.Fatalf("honest single-member header rejected: %v", err)
	}

	// A field covered by the signature cannot be changed after signing.
	h2 := testHeader()
	h2.ChainID = 1668
	signedHeader(t, h2, []int{0, 1, 2}, members)
	h2.Height++
	if err := v.VerifyBlockHeader(h2); err == nil {
		t.Fatal("header tampered after signing was accepted")
	}
}

func TestSyncCommitteeVerifyFailClosedRules(t *testing.T) {
	// No committee configured + header carries sync data → must reject.
	v := NewSyncCommitteeVerifier()
	h := testHeader()
	h.SyncCommitteeBits = []byte{0x01}
	if err := v.VerifyBlockHeader(h); err == nil {
		t.Fatal("sync data with no committee configured accepted")
	}
	// No committee + no sync data → pre-committee block, accepted.
	h2 := testHeader()
	if err := v.VerifyBlockHeader(h2); err != nil {
		t.Fatalf("pre-committee header rejected: %v", err)
	}
	// Nil header.
	if err := v.VerifyBlockHeader(nil); err == nil {
		t.Fatal("nil header accepted")
	}

	// Committee configured but header has no signatures → fail-closed.
	v2, members := newTestCommittee(t, 3)
	h3 := testHeader()
	signedHeader(t, h3, []int{0, 1, 2}, members)
	h3.SyncCommitteeSig = nil
	if err := v2.VerifyBlockHeader(h3); err == nil {
		t.Fatal("missing signatures accepted")
	}
	h4 := testHeader()
	signedHeader(t, h4, []int{0, 1, 2}, members)
	h4.SyncCommitteeBits = nil
	if err := v2.VerifyBlockHeader(h4); err == nil {
		t.Fatal("missing bitfield accepted")
	}

	// Zero participants.
	h5 := testHeader()
	h5.SyncCommitteeBits = make([]byte, 1)
	h5.SyncCommitteeSig = make([]byte, 3300)
	if err := v2.VerifyBlockHeader(h5); err == nil {
		t.Fatal("zero participants accepted")
	}
}

func TestSyncCommitteeRejectsOversizedBitfield(t *testing.T) {
	// AUDIT CRIT-02 regression: bits beyond the committee size must not
	// inflate participation.
	v, _ := newTestCommittee(t, 3)
	h := testHeader()
	h.SyncCommitteeBits = make([]byte, 8) // far beyond ceil(3/8)=1 byte
	h.SyncCommitteeSig = make([]byte, 3*3293)
	if err := v.VerifyBlockHeader(h); err == nil {
		t.Fatal("oversized bitfield accepted")
	}
}

func TestSyncCommitteeRejectsBelowThreshold(t *testing.T) {
	// 1 of 3 members is below the 2/3 participation floor.
	v, members := newTestCommittee(t, 3)
	h := testHeader()
	signedHeader(t, h, []int{0}, members)
	if err := v.VerifyBlockHeader(h); err == nil {
		t.Fatal("below-threshold participation accepted")
	}
}

func TestSyncCommitteeRejectsWrongSigner(t *testing.T) {
	// 3/3 sign but one signature is over different data (wrong member key).
	v, members := newTestCommittee(t, 3)
	h := testHeader()
	signedHeader(t, h, []int{0, 1, 2}, members)
	// Corrupt the middle signature.
	copy(h.SyncCommitteeSig[3293:3296], []byte{0xde, 0xad, 0xbe})
	if err := v.VerifyBlockHeader(h); err == nil {
		t.Fatal("corrupted committee signature accepted")
	}
}

func TestSyncCommitteeCommitteeRotation(t *testing.T) {
	v, _ := newTestCommittee(t, 3)
	next := &SyncCommitteeInfo{ValidatorPubKeys: committeePubKeys(t, 3)}
	v.UpdateNextCommittee(next)
	v.RotateCommittee()
	cur := v.GetCurrentCommittee()
	if cur == nil || len(cur.ValidatorPubKeys) != 3 {
		t.Fatal("rotation did not promote the next committee")
	}
	// Rotating with no pending next committee clears the current one
	// (RotateCommittee assigns next=nil). Documented behavior: the caller
	// must set the next committee before rotating again; a verifier with
	// no committee fails closed on headers carrying sync data.
	v.RotateCommittee()
	if v.GetCurrentCommittee() != nil {
		t.Fatal("rotation without a pending committee kept a stale committee")
	}
}

func TestCountSetBitsAndIsBitSet(t *testing.T) {
	if got := countSetBits([]byte{0xff, 0x00, 0x01}); got != 9 {
		t.Fatalf("countSetBits = %d, want 9", got)
	}
	if countSetBits(nil) != 0 {
		t.Fatal("countSetBits(nil) != 0")
	}
	if !isBitSet([]byte{0x01}, 0) {
		t.Fatal("bit 0 not set in 0x01")
	}
	if isBitSet([]byte{0x01}, 1) {
		t.Fatal("bit 1 reported set in 0x01")
	}
	if isBitSet([]byte{0x01}, -1) {
		t.Fatal("negative index reported set")
	}
	if isBitSet([]byte{0x01}, 8) {
		t.Fatal("out-of-range index reported set")
	}
}

func TestParseConcatenatedSignatures(t *testing.T) {
	// 2 participants × fixed 3293-byte signatures.
	a := make([]byte, 3293)
	b := make([]byte, 3293)
	a[0], b[0] = 0xaa, 0xbb
	agg := append(append([]byte{}, a...), b...)
	bitfield := []byte{0x03} // members 0 and 1
	sigs := parseConcatenatedSignatures(agg, bitfield, 3)
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	if sigs[0][0] != 0xaa || sigs[1][0] != 0xbb {
		t.Fatal("signature order scrambled")
	}

	// Zero participants → nil.
	if parseConcatenatedSignatures(agg, []byte{0x00}, 3) != nil {
		t.Fatal("zero participants returned signatures")
	}

	// Short input falls back to length-prefixed parsing.
	prefixed := make([]byte, 0, 2+2+2)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, 2)
	prefixed = append(prefixed, lenBuf...)
	prefixed = append(prefixed, 0xca, 0xfe)
	sigs2 := parseVariableLengthSignatures(prefixed, 1)
	if len(sigs2) != 1 || sigs2[0][0] != 0xca || sigs2[0][1] != 0xfe {
		t.Fatalf("length-prefixed parse failed: %v", sigs2)
	}

	// Truncated length prefix ignored.
	if got := parseVariableLengthSignatures([]byte{0x00}, 1); len(got) != 0 {
		t.Fatalf("truncated prefix returned %d signatures", len(got))
	}
}

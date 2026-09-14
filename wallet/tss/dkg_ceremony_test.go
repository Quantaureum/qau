// Quantaureum Node source, version 1.0.0.
// dkg_ceremony_test.go — round-trip + wire-compat tests for the DKG
// ceremony helpers in dkg_ceremony.go.
//
// These tests verify three critical invariants:
//  1. EncryptSingleShareBlob -> DecryptSingleShareBlob round-trip preserves
//     the original plaintext byte-for-byte.
//  2. A blob encrypted with EncryptSingleShareBlob can be decrypted by the
//     node-side ImportKeySharesEncrypted (which uses the same tssMagic AAD
//     and scrypt+AES-256-GCM scheme) — this is the wire-compat guarantee.
//  3. EncryptSingleShareBlob fails on empty password / empty plaintext.
package tss

import (
	"bytes"
	"testing"
)

func TestEncryptSingleShareBlob_RoundTrip(t *testing.T) {
	password := []byte("very-secure-ceremony-password!!")
	plaintext := []byte("some single-share wire blob")

	enc, err := EncryptSingleShareBlob(plaintext, password)
	if err != nil {
		t.Fatalf("EncryptSingleShareBlob: %v", err)
	}
	defer SecureZero(enc)

	// Sanity: file should start with tssMagic
	if string(enc[:len(tssMagic)]) != string(tssMagic) {
		t.Fatalf("encrypted blob missing tssMagic prefix; got %x", enc[:6])
	}

	got, err := DecryptSingleShareBlob(enc, password)
	if err != nil {
		t.Fatalf("DecryptSingleShareBlob: %v", err)
	}
	defer SecureZero(got)

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: want %x, got %x", plaintext, got)
	}
}

func TestEncryptSingleShareBlob_WrongPasswordFails(t *testing.T) {
	goodPwd := []byte("good-ceremony-password-123")
	badPwd := []byte("wrong-ceremony-password!")
	plaintext := []byte("another single-share blob")

	enc, err := EncryptSingleShareBlob(plaintext, goodPwd)
	if err != nil {
		t.Fatalf("EncryptSingleShareBlob: %v", err)
	}
	defer SecureZero(enc)

	if _, err := DecryptSingleShareBlob(enc, badPwd); err == nil {
		t.Fatal("expected decryption to fail with wrong password; got nil err")
	}
}

func TestEncryptSingleShareBlob_NodeSideImportPathCompat(t *testing.T) {
	// WIRE-COMPAT: A blob encrypted with EncryptSingleShareBlob MUST
	// decrypt cleanly through ImportKeySharesEncrypted (the node-side
	// path). If this test fails, the ceremony tool's per-validator share
	// files cannot be loaded by qaud on startup — the whole DKG workflow
	// breaks for production deployments.
	password := []byte("production-ceremony-pwd!!")
	cfg := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	ceremonyMgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager (ceremony): %v", err)
	}
	defer ceremonyMgr.ZeroizeAllShares()

	if _, err := ceremonyMgr.GenerateKeyShares(); err != nil {
		t.Fatalf("GenerateKeyShares: %v", err)
	}

	groupKeyBlob, err := ceremonyMgr.ExportGroupPublicKey()
	if err != nil {
		t.Fatalf("ExportGroupPublicKey: %v", err)
	}

	// Pick participant 1's share and build the single-share wire blob
	// using the same layout as cmd/tss_dkg_gen.singleShareBlob.
	share1, err := ceremonyMgr.GetQTDShare(1)
	if err != nil {
		t.Fatalf("GetQTDShare(1): %v", err)
	}
	shareBytes := share1.Encode()
	if shareBytes == nil {
		t.Fatal("share Encode() returned nil")
	}

	// Build blob: uint16 count=1 || uint32 shareLen || shareBytes || uint32 gpkLen || gpkBytes
	buf := make([]byte, 0, 2+4+len(shareBytes)+4+len(groupKeyBlob))
	buf = appendUint16BE(buf, 1)
	buf = appendUint32BE(buf, uint32(len(shareBytes)))
	buf = append(buf, shareBytes...)
	buf = appendUint32BE(buf, uint32(len(groupKeyBlob)))
	buf = append(buf, groupKeyBlob...)

	enc, err := EncryptSingleShareBlob(buf, password)
	if err != nil {
		t.Fatalf("EncryptSingleShareBlob: %v", err)
	}
	defer SecureZero(enc)
	SecureZero(buf)

	// Now impersonate a validator node: create a fresh TSSManager, and
	// feed the encrypted blob through ImportKeySharesEncrypted (the
	// node-side path). If wire-compat holds, the manager ends up with
	// exactly ONE share keyed by ParticipantID=1.
	nodeMgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager (node): %v", err)
	}
	defer nodeMgr.ZeroizeAllShares()

	if err := nodeMgr.ImportKeySharesEncrypted(enc, password); err != nil {
		t.Fatalf("ImportKeySharesEncrypted wire-compat FAIL: %v", err)
	}

	if got := nodeMgr.ShareCount(); got != 1 {
		t.Fatalf("wire-compat: expected ShareCount=1 after single-share import, got %d", got)
	}
	if !nodeMgr.HasGroupPublicKey() {
		t.Fatal("wire-compat: HasGroupPublicKey() should be true after import (group key embedded in blob)")
	}
	// The group public key from the imported blob must match the
	// ceremony manager's group public key byte-for-byte. Otherwise the
	// validator would never produce signatures the chain accepts.
	gotGPK := nodeMgr.GroupPublicKey()
	wantGPK := ceremonyMgr.GroupPublicKey()
	if !bytes.Equal(gotGPK, wantGPK) {
		t.Fatalf("wire-compat: group public key mismatch (want %x..., got %x...)",
			shortFP(wantGPK), shortFP(gotGPK))
	}

	// The imported share's ParticipantID must be 1 (the embedded value).
	// ImportKeyShares uses share.ParticipantID (decoded from shareBytes)
	// as the map key — verifying this guards against accidental swap.
	_, err = nodeMgr.GetQTDShare(1)
	if err != nil {
		t.Fatalf("wire-compat: GetQTDShare(1) should succeed after import: %v", err)
	}

	// Cross-check: validator should NOT have shares for participants 2+
	if _, err := nodeMgr.GetQTDShare(2); err == nil {
		t.Fatal("wire-compat: validator should NOT have share for participant 2")
	}
}

func TestEncryptSingleShareBlob_InputValidation(t *testing.T) {
	if _, err := EncryptSingleShareBlob([]byte("x"), nil); err == nil {
		t.Fatal("expected error for nil password")
	}
	if _, err := EncryptSingleShareBlob(nil, []byte("password")); err == nil {
		t.Fatal("expected error for nil plaintext")
	}
	if _, err := EncryptSingleShareBlob(nil, nil); err == nil {
		t.Fatal("expected error for both nil inputs")
	}
}

func TestSecureZero_WipesBytes(t *testing.T) {
	b := []byte("sensitive material")
	SecureZero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %x", i, v)
		}
	}
}

// appendUint16BE / appendUint32BE mirror binary.BigEndian.AppendUint* but
// are defined locally so the test file does not need to import encoding/binary
// only for these helpers. Keeps the test file's import surface tiny.
func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// shortFP returns the first 8 bytes of b as hex for log-friendly fingerprints.
func shortFP(b []byte) []byte {
	if len(b) >= 8 {
		return b[:8]
	}
	return b
}

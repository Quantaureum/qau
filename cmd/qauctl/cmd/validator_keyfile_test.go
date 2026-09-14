// Quantaureum Node source, version 1.0.0.
package cmd

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// writeKeyFile writes the given content to a temporary .key file and returns
// the absolute path. Uses t.TempDir() which is cleaned up automatically.
func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// TestReadAndValidateKeyFile_Dilithium3HexPlaintext covers the legacy
// `dilithium3:priv[:pub]` plaintext format. The returned address must match
// the public key's Address() result.
func TestReadAndValidateKeyFile_Dilithium3HexPlaintext(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privHex := hex.EncodeToString(kp.Private.Bytes())
	pubHex := hex.EncodeToString(kp.Public.Bytes())
	content := "dilithium3:" + privHex + ":" + pubHex

	path := writeKeyFile(t, content)
	_, addr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile (plaintext): %v", err)
	}
	expected := kp.Public.Address()
	expectedArr := [20]byte(expected)
	if addr != expectedArr {
		t.Fatalf("plaintext: address mismatch\n got  = %x\n want = %x", addr, expectedArr)
	}
}

// TestReadAndValidateKeyFile_Dilithium3ConcatenatedPrivPub covers the format
// the node itself writes for /var/lib/quantaureum/validator.key:
// `dilithium3:<priv||pub>`, i.e. the two keys concatenated with no separator
// (4000 + 1952 = 5952 bytes, 11904 hex chars).
//
// Before the fix this file — which the node loads without complaint — was
// rejected by every qauctl command that reads a key file:
//
//	invalid private key size: got 5952 bytes, expected 4000
//
// which blocked `qauctl genesis show-validators` and `genesis generate` on the
// real validator keys.
func TestReadAndValidateKeyFile_Dilithium3ConcatenatedPrivPub(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privBytes := kp.Private.Bytes()
	pubBytes := kp.Public.Bytes()
	if len(privBytes) != crypto.Dilithium3PrivateKeySize || len(pubBytes) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("unexpected key sizes: priv=%d pub=%d", len(privBytes), len(pubBytes))
	}
	content := "dilithium3:" + hex.EncodeToString(append(append([]byte{}, privBytes...), pubBytes...))

	path := writeKeyFile(t, content)
	_, addr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile (concatenated priv||pub): %v", err)
	}
	expected := [20]byte(kp.Public.Address())
	if addr != expected {
		t.Fatalf("concatenated: address mismatch\n got  = %x\n want = %x", addr, expected)
	}
}

// TestReadAndValidateKeyFile_JSONKeystore_QAUBase32 exercises the encrypted
// JSON keystore format whose `address` field is encoded as a QAU base32
// string (e.g. "QAUCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIR"). Before the fix this
// path failed because it ran:
//
//	hex.DecodeString(strings.TrimPrefix("QAUCEIR...", "0x"))
//	// -> encoding/hex: invalid byte: U+0051 'Q'
//
// After the fix it uses types.ParseAddressWithFallback, which handles both
// QAU base32 and 0x-hex address encodings.
func TestReadAndValidateKeyFile_JSONKeystore_QAUBase32(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	qauAddr := kp.Public.Address().String()

	// Build a minimal keystore-like JSON with the QAU base32 address.
	content := `{"version":1,"address":"` + qauAddr + `","crypto":{"cipher":"aes-256-gcm","symmetric":{"iv":"deterministic-iv","ciphertext":"deadbeef"}},"created_at":1234567890}`

	path := writeKeyFile(t, content)
	_, addr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile (JSON keystore / QAU base32): %v", err)
	}
	expected := kp.Public.Address()
	expectedArr := [20]byte(expected)
	if addr != expectedArr {
		t.Fatalf("JSON keystore / QAU base32: address mismatch\n got  = %x\n want = %x", addr, expectedArr)
	}
}

// TestReadAndValidateKeyFile_Dilithium3PrefixJSONMixed covers the mixed
// `dilithium3:{...}` format produced by some server-side key writers, where
// an encrypted JSON keystore is prefixed with the `dilithium3:` marker.
// Before the fix this path failed because the code stripped `dilithium3:`
// and tried to hex-decode the residual `{...}` JSON body, which immediately
// tripped on `{` (`invalid byte: U+007B '{'`).
//
// After the fix it detects the `{` after stripping the prefix and routes the
// content through the JSON keystore branch.
func TestReadAndValidateKeyFile_Dilithium3PrefixJSONMixed(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	qauAddr := kp.Public.Address().String()

	inner := `{"version":1,"address":"` + qauAddr + `","crypto":{"cipher":"aes-256-gcm","symmetric":{"iv":"x","ciphertext":"deadbeef"}},"created_at":1234567890}`
	content := "dilithium3:" + inner

	path := writeKeyFile(t, content)
	_, addr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile (dilithium3:+JSON mixed): %v", err)
	}
	expected := kp.Public.Address()
	expectedArr := [20]byte(expected)
	if addr != expectedArr {
		t.Fatalf("mixed: address mismatch\n got  = %x\n want = %x", addr, expectedArr)
	}
}

// TestReadAndValidateKeyFile_JSONKeystore_HexAddress covers the legacy 0x-hex
// address form to ensure the fix did not regress existing behavior for key
// files still using 0x-encoded addresses.
func TestReadAndValidateKeyFile_JSONKeystore_HexAddress(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	expected := kp.Public.Address()
	hexAddr := "0x" + hex.EncodeToString(expected[:])
	content := `{"version":1,"address":"` + hexAddr + `","crypto":{"cipher":"aes-256-gcm","symmetric":{"iv":"x","ciphertext":"deadbeef"}},"created_at":1234567890}`

	path := writeKeyFile(t, content)
	_, addr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile (JSON keystore / 0x hex): %v", err)
	}
	expectedArr := [20]byte(expected)
	if addr != expectedArr {
		t.Fatalf("JSON keystore / 0x hex: address mismatch\n got  = %x\n want = %x", addr, expectedArr)
	}
}

// _ keep types import declared even if some compiler-specific path drops it.
var _ types.Address

// _ keep sanitize-style no-op for future expansion.
var _ = hex.EncodeToString

// --- R92-KEYSEP regression tests ---
//
// Symptom before the fix:
//
//	qauctl genesis generate --validator-keys <file>
//	  -> failed to read validator key file: invalid hex in key file:
//	     encoding/hex: invalid byte: U+002B '+'
//
// Root cause: readAndValidateKeyFile / readPublicKeyFromKeyFile split the
// plaintext payload on ':' only, so the documented `dilithium3:<priv>+<pub>`
// form (crypto/generate.go:27, AGENTS.md) was rejected even though the node
// itself loads it fine (parseValidatorPrivateKeyFile filters to hex first).

func TestR92_ReadAndValidateKeyFile_PlusSeparator(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privHex := hex.EncodeToString(kp.Private.Bytes())
	pubHex := hex.EncodeToString(kp.Public.Bytes())
	wantAddr := kp.Public.Address()

	dir := t.TempDir()
	path := filepath.Join(dir, "plus.key")
	// Documented format: dilithium3:<privHex>+<pubHex>
	if err := os.WriteFile(path, []byte("dilithium3:"+privHex+"+"+pubHex+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, gotAddr, err := readAndValidateKeyFile(path)
	if err != nil {
		t.Fatalf("readAndValidateKeyFile rejected the documented '+' separator: %v", err)
	}
	if !bytes.Equal(gotAddr[:], wantAddr[:]) {
		t.Fatalf("address mismatch: got 0x%x want 0x%x", gotAddr, wantAddr)
	}

	gotPub, err := readPublicKeyFromKeyFile(path)
	if err != nil {
		t.Fatalf("readPublicKeyFromKeyFile rejected the documented '+' separator: %v", err)
	}
	if gotPub != pubHex {
		t.Fatalf("public key mismatch: got %d hex chars, want %d", len(gotPub), len(pubHex))
	}
}

func TestR92_SplitDilithium3KeyHex_SeparatorAgnostic(t *testing.T) {
	privHex := strings.Repeat("ab", crypto.Dilithium3PrivateKeySize)
	pubHex := strings.Repeat("cd", crypto.Dilithium3PublicKeySize)

	cases := []struct {
		name    string
		payload string
		wantPub string
	}{
		{"colon separator (legacy server writers)", privHex + ":" + pubHex, pubHex},
		{"plus separator (documented format)", privHex + "+" + pubHex, pubHex},
		{"concatenated (node-written validator.key)", privHex + pubHex, pubHex},
		{"newline separator", privHex + "\n" + pubHex, pubHex},
		{"private key only", privHex, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPriv, gotPub, err := splitDilithium3KeyHex(tc.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPriv != privHex {
				t.Fatalf("private half wrong: got %d chars want %d", len(gotPriv), len(privHex))
			}
			if gotPub != tc.wantPub {
				t.Fatalf("public half wrong: got %d chars want %d", len(gotPub), len(tc.wantPub))
			}
		})
	}
}

func TestR92_SplitDilithium3KeyHex_RejectsWrongLength(t *testing.T) {
	if _, _, err := splitDilithium3KeyHex("deadbeef"); err == nil {
		t.Fatal("expected error for a payload that is neither priv nor priv+pub length")
	}
}

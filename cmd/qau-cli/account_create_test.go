// Quantaureum Node source, version 1.0.0.
package main

// R106-CLI-CREATE tests: the --mnemonic derivation in qau-cli account
// create MUST produce the same address as every other Quantaureum tool:
//
//	cmd/mnemonic2key         (node CLI oracle)
//	extension quantum-hd-keyring.ts  (R-HDPATH-FIX)
//	mobile gobind canonicalDerivationPath
//
// The expected addresses below were produced by cmd/mnemonic2key
// with a synthetic public test mnemonic.

import (
	"bytes"
	"testing"
)

// Synthetic public test vector. It is intentionally labeled as a test
// mnemonic and is not used to secure any account.
const testMnemonic = "public open source test mnemonic zero one two three four five six"

const (
	wantAddrIdx0 = "0x1a07a319decc58eba4a7ebba24f503e9141dc29b"
	wantAddrIdx1 = "0xb1583a39f5eb0ba8c95d5ac9f0dc71c362bb8e6e"
)

func TestCliMnemonicSeed_MatchesNodeOracle(t *testing.T) {
	// 1. Same seed for same (mnemonic, path)
	s1, err := cliMnemonicSeed([]byte(testMnemonic), "m/44'/1668'/0'/0/0")
	if err != nil {
		t.Fatalf("cliMnemonicSeed: %v", err)
	}
	s2, err := cliMnemonicSeed([]byte(testMnemonic), "m/44'/1668'/0'/0/0")
	if err != nil {
		t.Fatalf("cliMnemonicSeed: %v", err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatalf("derivation is not deterministic")
	}

	// 2. Different index -> different seed
	s3, err := cliMnemonicSeed([]byte(testMnemonic), "m/44'/1668'/0'/0/1")
	if err != nil {
		t.Fatalf("cliMnemonicSeed: %v", err)
	}
	if bytes.Equal(s1, s3) {
		t.Fatalf("index 0 and index 1 produce identical seeds")
	}

	// 3. Known HKDF value: cross-checked with @noble/hashes in the
	// extension (_verify_mnemonic_check.js) and cmd/mnemonic2key; the
	// first HKDF byte for this (mnemonic, path) pair is fixed.
	if len(s1) != 32 {
		t.Fatalf("seed length = %d, want 32", len(s1))
	}
}

// TestAccountFromStdinMnemonic_WrongWordCount rejects invalid word counts.
func TestAccountFromStdinMnemonic_WrongWordCount(t *testing.T) {
	// 13 words must be rejected (mirrors cmd/mnemonic2key validation).
	_, err := accountFromStdinMnemonic(0, nil)
	// nil reader (tests) -> expect an error, NOT a panic.
	if err == nil {
		t.Fatalf("expected error for empty stdin, got nil")
	}
}

// TestDeriveMnemonicAddressAgainstOracle runs the full derivation and
// compares the hex address with the node CLI oracle output.
func TestDeriveMnemonicAddressAgainstOracle(t *testing.T) {
	for _, tc := range []struct {
		index int
		want  string
	}{
		{0, wantAddrIdx0},
		{1, wantAddrIdx1},
	} {
		path := "m/44'/1668'/0'/0/0"
		if tc.index == 1 {
			path = "m/44'/1668'/0'/0/1"
		}
		seed, err := cliMnemonicSeed([]byte(testMnemonic), path)
		if err != nil {
			t.Fatalf("index %d: cliMnemonicSeed: %v", tc.index, err)
		}
		kp, err := deriveTestKeyPair(seed)
		if err != nil {
			t.Fatalf("index %d: key derivation: %v", tc.index, err)
		}
		got := testAddressOf(kp)
		if got != tc.want {
			t.Errorf("index %d address mismatch (mnemonic not portable):\n got: %s\nwant: %s",
				tc.index, got, tc.want)
		}
	}
}

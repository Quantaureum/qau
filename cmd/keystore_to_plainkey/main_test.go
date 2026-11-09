package main

import (
	"strings"
	"testing"
)

func clearKeyExportEnv(t *testing.T) {
	t.Helper()
	t.Setenv("QAU_NETWORK", "")
	t.Setenv("QAU_CHAIN_ID", "")
	t.Setenv("QAU_NETWORK_ID", "")
	t.Setenv("QAU_PRODUCTION", "")
	t.Setenv(plaintextExportOptInEnv, "")
}

// SECURITY (audit N-18): an unset -o must no longer silently dump the
// decrypted private key to stdout.
func TestN18_StdoutExportRequiresOptIn(t *testing.T) {
	clearKeyExportEnv(t)

	err := requireExplicitOutput("")
	if err == nil {
		t.Fatal("stdout export must be refused without an explicit opt-in")
	}
	if !strings.Contains(err.Error(), plaintextExportOptInEnv) {
		t.Fatalf("error must name the opt-in variable, got: %v", err)
	}
}

func TestN18_StdoutExportAllowedWithOptIn(t *testing.T) {
	clearKeyExportEnv(t)
	t.Setenv("QAU_NETWORK", "devnet")
	t.Setenv(plaintextExportOptInEnv, "1")

	if err := requireExplicitOutput(""); err != nil {
		t.Fatalf("stdout export with explicit opt-in must be allowed: %v", err)
	}
}

// On a declared devnet an explicit output path needs no opt-in (mode 0600 is
// enforced downstream).
func TestN18_ExplicitOutputNeedsNoOptInOnDevnet(t *testing.T) {
	clearKeyExportEnv(t)
	t.Setenv("QAU_NETWORK", "devnet")

	if err := requireExplicitOutput("/tmp/qau-plain.key"); err != nil {
		t.Fatalf("explicit -o output on devnet must be allowed without an opt-in: %v", err)
	}
}

// AUDIT node/cmd-plaintext-key-export-gate: on mainnet, -o alone must not be
// enough to decrypt a validator key to disk.
func TestPlaintextExportGate_MainnetOutputRequiresConfirmation(t *testing.T) {
	clearKeyExportEnv(t)
	t.Setenv("QAU_CHAIN_ID", "1668")

	err := requireExplicitOutput("/tmp/qau-plain.key")
	if err == nil {
		t.Fatal("mainnet -o export must be refused without an explicit confirmation")
	}
	if !strings.Contains(err.Error(), plaintextExportOptInEnv) {
		t.Fatalf("error must name the confirmation variable, got: %v", err)
	}

	t.Setenv(plaintextExportOptInEnv, "1")
	if err := requireExplicitOutput("/tmp/qau-plain.key"); err != nil {
		t.Fatalf("mainnet -o export with explicit confirmation must be allowed: %v", err)
	}
}

// Fail-closed: an environment that declares no network is mainnet (chain 1668).
func TestPlaintextExportGate_UndeclaredDefaultsToMainnet(t *testing.T) {
	clearKeyExportEnv(t)

	if err := requireExplicitOutput("/tmp/qau-plain.key"); err == nil {
		t.Fatal("undeclared network must be treated as mainnet and refuse -o export")
	}
}

// Only the literal "1" counts — "true"/"yes" must not accidentally unlock it.
func TestN18_OptInIsStrict(t *testing.T) {
	for _, v := range []string{"true", "yes", "1 ", "0"} {
		t.Run(v, func(t *testing.T) {
			clearKeyExportEnv(t)
			t.Setenv("QAU_NETWORK", "devnet")
			t.Setenv(plaintextExportOptInEnv, v)
			if err := requireExplicitOutput(""); err == nil {
				t.Fatalf("%q must not unlock stdout export", v)
			}
		})
	}
}

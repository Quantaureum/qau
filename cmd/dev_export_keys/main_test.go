package main

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/cmd/internal/keyexportgate"
)

func clearExportEnv(t *testing.T) {
	t.Helper()
	t.Setenv("QAU_NETWORK", "")
	t.Setenv("QAU_CHAIN_ID", "")
	t.Setenv("QAU_NETWORK_ID", "")
	t.Setenv("QAU_PRODUCTION", "")
	t.Setenv(plaintextExportOptInEnv, "")
}

// SECURITY (audit N-18): bulk plaintext export must require an explicit
// opt-in, not just a keystore password.
func TestN18_DevExportRequiresExplicitOptIn(t *testing.T) {
	clearExportEnv(t)

	err := requirePlaintextExportOptIn()
	if err == nil {
		t.Fatal("plaintext export must be refused without an explicit opt-in")
	}
	if !strings.Contains(err.Error(), plaintextExportOptInEnv) {
		t.Fatalf("error must name the opt-in variable, got: %v", err)
	}
}

// SECURITY (audit N-18): mainnet is refused even with an explicit opt-in.
func TestN18_DevExportRefusesMainnet(t *testing.T) {
	cases := []struct{ name, value string }{
		{"QAU_NETWORK", "mainnet"},
		{"QAU_NETWORK", "MainNet"},
		{"QAU_NETWORK", "1668"},
		{"QAU_CHAIN_ID", "1668"},
		{"QAU_NETWORK_ID", "1668"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			clearExportEnv(t)
			t.Setenv(plaintextExportOptInEnv, "1")
			t.Setenv(tc.name, tc.value)

			err := requirePlaintextExportOptIn()
			if err == nil {
				t.Fatalf("mainnet context (%s=%s) must be refused", tc.name, tc.value)
			}
			if !strings.Contains(err.Error(), "mainnet") {
				t.Fatalf("error must say mainnet, got: %v", err)
			}
		})
	}
}

// The devnet path with the opt-in must remain allowed.
func TestN18_DevExportAllowsDevnetWithOptIn(t *testing.T) {
	clearExportEnv(t)
	t.Setenv(plaintextExportOptInEnv, "1")
	t.Setenv("QAU_CHAIN_ID", "1333")

	if err := requirePlaintextExportOptIn(); err != nil {
		t.Fatalf("devnet export with explicit opt-in must be allowed: %v", err)
	}
}

// AUDIT node/cmd-plaintext-key-export-gate: the gate is fail-closed. An
// environment that declares no network must be treated as mainnet, because the
// shipped binaries default to chain 1668.
func TestPlaintextExportGate_DefaultsToMainnet(t *testing.T) {
	clearExportEnv(t)
	if !keyexportgate.Mainnet() {
		t.Fatal("undeclared network must be treated as mainnet")
	}
	t.Setenv(plaintextExportOptInEnv, "1")
	if err := requirePlaintextExportOptIn(); err == nil {
		t.Fatal("undeclared network with opt-in must still be refused as mainnet")
	}
}

// A declared devnet must not be treated as mainnet.
func TestPlaintextExportGate_DeclaredDevnetIsNotMainnet(t *testing.T) {
	clearExportEnv(t)
	t.Setenv("QAU_CHAIN_ID", "1669")
	if keyexportgate.Mainnet() {
		t.Fatal("testnet chain id must not be treated as mainnet")
	}
}

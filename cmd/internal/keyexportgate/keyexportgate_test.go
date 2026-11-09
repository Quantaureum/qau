// Quantaureum Node source, version 1.0.0.
package keyexportgate

import "testing"

// clearGateEnv resets every variable the gate consults, keeping test cases
// independent.
func clearGateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"QAU_PRODUCTION", "QAU_CHAIN_ID", "QAU_NETWORK_ID", "QAU_NETWORK"} {
		t.Setenv(k, "")
	}
}

// TestMainnet covers the fail-closed decision table, including the
// QAU_PRODUCTION=1 override that must win over every non-mainnet declaration.
func TestMainnet(t *testing.T) {
	cases := []struct {
		name       string
		production string
		chainID    string
		networkID  string
		network    string
		want       bool
	}{
		// Fail-closed default: nothing declared means mainnet.
		{name: "nothing declared", want: true},
		// QAU_PRODUCTION=1 forces mainnet even when a devnet is declared.
		{name: "production forces mainnet over devnet", production: "1", network: "devnet", want: true},
		{name: "production forces mainnet over testnet chain id", production: "1", chainID: "1669", want: true},
		{name: "production is whitespace trimmed", production: " 1 ", network: "devnet", want: true},
		{name: "production not set keeps testnet", production: "0", network: "testnet", want: false},
		// Explicit chain ID decides when production is unset.
		{name: "devnet chain id", chainID: "1333", want: false},
		{name: "testnet chain id", chainID: "1669", want: false},
		{name: "mainnet chain id", chainID: "1668", want: true},
		{name: "network id wins over QAU_NETWORK", networkID: "1333", network: "mainnet", want: false},
		// Named network fallback.
		{name: "network devnet", network: "devnet", want: false},
		{name: "network testnet", network: "testnet", want: false},
		{name: "network mainnet", network: "mainnet", want: true},
		{name: "unknown network stays fail-closed", network: "something-else", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearGateEnv(t)
			t.Setenv("QAU_PRODUCTION", tc.production)
			t.Setenv("QAU_CHAIN_ID", tc.chainID)
			t.Setenv("QAU_NETWORK_ID", tc.networkID)
			t.Setenv("QAU_NETWORK", tc.network)
			if got := Mainnet(); got != tc.want {
				t.Fatalf("Mainnet() = %v, want %v", got, tc.want)
			}
		})
	}
}

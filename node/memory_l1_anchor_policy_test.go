// Quantaureum Node source, version 1.0.0.
package node

import (
	"strings"
	"testing"
)

// F-18 regression: a memory-backed L1 anchor must not be used on non-devnet
// networks unless the operator explicitly opts in.
func TestCheckMemoryL1AnchorPolicy(t *testing.T) {
	tests := []struct {
		name        string
		networkID   uint64
		allowEnv    string
		wantErr     bool
		errContains string
	}{
		{name: "devnet without opt-in", networkID: DevnetNetworkID, allowEnv: ""},
		{name: "devnet with opt-in", networkID: DevnetNetworkID, allowEnv: "1"},
		{name: "devnet with unrelated env value", networkID: DevnetNetworkID, allowEnv: "0"},
		{name: "testnet without opt-in", networkID: TestnetNetworkID, allowEnv: "", wantErr: true, errContains: "QAU_ALLOW_MEMORY_L1_ANCHOR=1"},
		{name: "testnet with zero opt-in", networkID: TestnetNetworkID, allowEnv: "0", wantErr: true, errContains: "memory L1 anchor"},
		{name: "testnet with opt-in", networkID: TestnetNetworkID, allowEnv: "1"},
		{name: "mainnet without opt-in", networkID: MainnetNetworkID, allowEnv: "", wantErr: true, errContains: "memory L1 anchor"},
		{name: "mainnet with opt-in", networkID: MainnetNetworkID, allowEnv: "1"},
		{name: "unknown network without opt-in", networkID: 424242, allowEnv: "", wantErr: true, errContains: "424242"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMemoryL1AnchorPolicy(tc.networkID, tc.allowEnv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("network %d allowEnv %q: expected error, got nil", tc.networkID, tc.allowEnv)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("network %d allowEnv %q: error %q does not contain %q", tc.networkID, tc.allowEnv, err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("network %d allowEnv %q: expected nil error, got %v", tc.networkID, tc.allowEnv, err)
			}
		})
	}
}

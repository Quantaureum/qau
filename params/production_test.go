// Quantaureum Node source, version 1.0.0.
package params

import (
	"os"
	"testing"
)

// R31-HIGH-1 tests: the centralized production-mode determination and the
// fail-closed opt-in guards for the known-unsafe parallel QVM / JIT paths.

func setenvs(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{"QAU_PRODUCTION", "QAU_ENABLE_PARALLEL_QVM", "QAU_ENABLE_JIT"} {
		os.Unsetenv(k)
	}
	for k, v := range kv {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for _, k := range []string{"QAU_PRODUCTION", "QAU_ENABLE_PARALLEL_QVM", "QAU_ENABLE_JIT"} {
			os.Unsetenv(k)
		}
	})
}

func TestIsProduction_ExplicitEnv(t *testing.T) {
	setenvs(t, map[string]string{"QAU_PRODUCTION": "1"})
	if !IsProduction(DevnetChainID) {
		t.Fatal("QAU_PRODUCTION=1 must force production mode on any network")
	}
}

func TestIsProduction_MainnetNetworkID(t *testing.T) {
	setenvs(t, nil) // no env
	// The R31-HIGH-1 backstop: a mainnet node is production by definition,
	// even when the operator forgot to set QAU_PRODUCTION.
	if !IsProduction(MainnetChainID) {
		t.Fatal("mainnet chain ID must imply production mode (R31-HIGH-1 fail-closed backstop)")
	}
	if IsProduction(TestnetChainID) {
		t.Fatal("testnet without QAU_PRODUCTION must NOT be production mode")
	}
	if IsProduction(DevnetChainID) {
		t.Fatal("devnet without QAU_PRODUCTION must NOT be production mode")
	}
	// Unknown network: not production by ID (env still applies).
	if IsProduction(999999) {
		t.Fatal("unknown network ID must not imply production")
	}
}

func TestParallelQVMAllowed_FailClosed(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		networkID uint64
		want      bool
	}{
		{"no env, devnet, config-on", nil, DevnetChainID, false}, // THE fix: config alone no longer arms it
		{"explicit opt-in, devnet", map[string]string{"QAU_ENABLE_PARALLEL_QVM": "1"}, DevnetChainID, true},
		{"opt-in but mainnet", map[string]string{"QAU_ENABLE_PARALLEL_QVM": "1"}, MainnetChainID, false}, // production always wins
		{"opt-in but QAU_PRODUCTION", map[string]string{"QAU_ENABLE_PARALLEL_QVM": "1", "QAU_PRODUCTION": "1"}, DevnetChainID, false},
		{"no env, mainnet", nil, MainnetChainID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.env)
			if got := ParallelQVMAllowed(tc.networkID); got != tc.want {
				t.Fatalf("ParallelQVMAllowed(%d) = %v, want %v", tc.networkID, got, tc.want)
			}
		})
	}
}

func TestJITAllowed_FailClosed(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		networkID uint64
		want      bool
	}{
		{"no opt-in, devnet", nil, DevnetChainID, false},
		{"explicit opt-in, devnet", map[string]string{"QAU_ENABLE_JIT": "1"}, DevnetChainID, true},
		{"opt-in but mainnet", map[string]string{"QAU_ENABLE_JIT": "1"}, MainnetChainID, false},
		{"opt-in but QAU_PRODUCTION", map[string]string{"QAU_ENABLE_JIT": "1", "QAU_PRODUCTION": "1"}, DevnetChainID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.env)
			if got := JITAllowed(tc.networkID); got != tc.want {
				t.Fatalf("JITAllowed(%d) = %v, want %v", tc.networkID, got, tc.want)
			}
		})
	}
}

func TestEnvOnlyVariants(t *testing.T) {
	setenvs(t, nil)
	if IsProductionEnv() {
		t.Fatal("no env → not production")
	}
	if ParallelQVMAllowedEnv() {
		t.Fatal("no opt-in → parallel QVM not allowed")
	}
	if JITAllowedEnv() {
		t.Fatal("no opt-in → JIT not allowed")
	}
	setenvs(t, map[string]string{"QAU_ENABLE_PARALLEL_QVM": "1", "QAU_ENABLE_JIT": "1"})
	if !ParallelQVMAllowedEnv() {
		t.Fatal("opt-in on non-production → parallel allowed")
	}
	if !JITAllowedEnv() {
		t.Fatal("opt-in on non-production → JIT allowed")
	}
	setenvs(t, map[string]string{"QAU_PRODUCTION": "1", "QAU_ENABLE_PARALLEL_QVM": "1", "QAU_ENABLE_JIT": "1"})
	if ParallelQVMAllowedEnv() || JITAllowedEnv() {
		t.Fatal("production must override both opt-ins")
	}
}

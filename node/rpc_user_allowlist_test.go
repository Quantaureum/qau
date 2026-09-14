// Quantaureum Node source, version 1.0.0.
package node

import (
	"strings"
	"testing"
)

// R74-STAKE-ALLOWLIST: the staking/DeFi RPC user allowlist is explicit opt-in.
// These cases pin the policy decision itself, because the bug it replaces was
// not a crash but a silent policy: production filled the list with the genesis
// validators and enforced it, so every ordinary user was rejected with -32003.

func TestResolveRPCUserAllowlist_EmptyMeansPermissionless(t *testing.T) {
	for name, entries := range map[string][]string{
		"nil":              nil,
		"empty slice":      {},
		"blank entry":      {""},
		"whitespace entry": {"   "},
	} {
		addrs, enforce, err := resolveRPCUserAllowlist(entries, "")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if enforce {
			t.Errorf("%s: enforcement must stay off with nothing to enforce", name)
		}
		if len(addrs) != 0 {
			t.Errorf("%s: expected no addresses, got %d", name, len(addrs))
		}
	}
}

func TestResolveRPCUserAllowlist_ConfiguredEnablesFailClosed(t *testing.T) {
	addrs, enforce, err := resolveRPCUserAllowlist(
		[]string{"0x9528fec867f70e4307f8032cec7cfac6bf42f17c"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enforce {
		t.Error("a configured allowlist must enable fail-closed enforcement")
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	if got := addrs[0].ToHexAddress(); !strings.EqualFold(got, "0x9528fec867f70e4307f8032cec7cfac6bf42f17c") {
		t.Errorf("address round-trip mismatch: got %s", got)
	}
}

func TestResolveRPCUserAllowlist_EnvOverridesConfig(t *testing.T) {
	configured := []string{"0x9528fec867f70e4307f8032cec7cfac6bf42f17c"}
	env := "0x464fa238475a22a6b7d024d9c29e0cf8200e638c, 0xea6bae0757e893f1d31aafc9785178543bc2329d"

	addrs, enforce, err := resolveRPCUserAllowlist(configured, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enforce {
		t.Fatal("expected enforcement")
	}
	if len(addrs) != 2 {
		t.Fatalf("env must replace the config list, got %d addresses", len(addrs))
	}
	for _, addr := range addrs {
		if strings.EqualFold(addr.ToHexAddress(), configured[0]) {
			t.Error("config entry leaked through even though the env var was set")
		}
	}
}

func TestResolveRPCUserAllowlist_Deduplicates(t *testing.T) {
	addrs, _, err := resolveRPCUserAllowlist([]string{
		"0x9528fec867f70e4307f8032cec7cfac6bf42f17c",
		"9528fec867f70e4307f8032cec7cfac6bf42f17c",
	}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected the duplicate to collapse, got %d addresses", len(addrs))
	}
}

func TestResolveRPCUserAllowlist_InvalidEntryIsAnError(t *testing.T) {
	// Fail loudly at startup. Dropping the entry (what initRPC used to do for
	// genesis validators) would silently change the policy: a typo in one of
	// two entries would half-open the node without any signal.
	if _, _, err := resolveRPCUserAllowlist([]string{"not-an-address"}, ""); err == nil {
		t.Fatal("expected an error for an unparsable allowlist entry")
	}

	if _, _, err := resolveRPCUserAllowlist(nil, "0x9528fec867f70e4307f8032cec7cfac6bf42f17c,zzz"); err == nil {
		t.Fatal("expected an error for an unparsable entry in the env override")
	}
}

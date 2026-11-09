// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// Run-4 P0-1 / D-32 regression tests: the local all-shares QTD sealing path
// (AggregatePartialSignatures → SignWithRetry) must be fail-closed on mainnet
// whenever a single node holds more than one DKG share and is asked to seal
// with more than one sealer, unless the operator explicitly disarms it via
// the tri-state config switch.
package node

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/wallet/tss"
)

// newAllSharesTestManager builds a TSSManager that actually holds
// TotalShares locally (as an imported full share file would).
func newAllSharesTestManager(t *testing.T, threshold, totalShares int) *tss.TSSManager {
	t.Helper()
	config := tss.DefaultTSSConfig()
	config.Threshold, config.TotalShares = threshold, totalShares
	manager, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatalf("GenerateKeyShares: %v", err)
	}
	if manager.ShareCount() != totalShares {
		t.Fatalf("test setup: expected %d loaded shares, got %d", totalShares, manager.ShareCount())
	}
	return manager
}

// TestP01_MainnetLocalAllSharesSealingRefused pins the core fix: mainnet,
// more than one loaded share, more than one sealer → refusal.
func TestP01_MainnetLocalAllSharesSealingRefused(t *testing.T) {
	manager := newAllSharesTestManager(t, 2, 3)
	defer manager.ZeroizeAllShares()

	adapter := &tssSignerAdapter{
		tss: manager,
		node: &Node{config: &Config{
			NetworkID: MainnetNetworkID,
		}},
	}

	_, err := adapter.AggregatePartialSignatures([]int{0, 1, 2}, nil, []byte("p01-mainnet-refusal"))
	if err == nil {
		t.Fatal("P0-1 regression: mainnet local all-shares sealing was accepted")
	}
	if !strings.Contains(err.Error(), "fail-closed on mainnet") {
		t.Fatalf("expected the all-shares refusal, got: %v", err)
	}
}

// TestP01_TestnetLocalAllSharesUnaffected guards against over-blocking:
// devnet/testnet keep the local path (documented single-node topology).
func TestP01_TestnetLocalAllSharesUnaffected(t *testing.T) {
	manager := newAllSharesTestManager(t, 2, 3)
	defer manager.ZeroizeAllShares()

	for _, networkID := range []uint64{1337, 1333} {
		adapter := &tssSignerAdapter{
			tss:  manager,
			node: &Node{config: &Config{NetworkID: networkID}},
		}
		_, err := adapter.AggregatePartialSignatures([]int{0, 1, 2}, nil, []byte("p01-testnet"))
		if err != nil && strings.Contains(err.Error(), "fail-closed on mainnet") {
			t.Fatalf("network %d: non-mainnet networks must keep the local path, got: %v", networkID, err)
		}
	}
}

// TestP01_RollbackSwitchDisarmsRefusal pins the tri-state rollback value:
// an explicit 0 keeps the pre-run-4 behavior on mainnet (WARN, no refusal).
func TestP01_RollbackSwitchDisarmsRefusal(t *testing.T) {
	manager := newAllSharesTestManager(t, 2, 3)
	defer manager.ZeroizeAllShares()

	rollback := uint64(0)
	adapter := &tssSignerAdapter{
		tss: manager,
		node: &Node{config: &Config{
			NetworkID:                   MainnetNetworkID,
			QTDLocalAllSharesActivation: &rollback,
		}},
	}

	_, err := adapter.AggregatePartialSignatures([]int{0, 1, 2}, nil, []byte("p01-rollback"))
	if err != nil && strings.Contains(err.Error(), "fail-closed on mainnet") {
		t.Fatalf("rollback switch must disarm the refusal, got: %v", err)
	}
}

// Note on the production-sampled single-share topology (e.g. 1-of-4 loaded):
// it is kept out of the refusal branch by the ShareCount() > 1 condition
// itself, and NewTSSManager refuses threshold=1 (R33 CONS-05), so no test
// manager can be constructed in that shape; the config-level guard
// (TSSTotalShares on mainnet, Validate()) covers the configured equivalent.

// TestLocalAllSharesActivationEffective_Resolution pins the tri-state
// resolution table: absent = network default (armed on mainnet only),
// explicit values win, permanent off resolves to 0.
func TestLocalAllSharesActivationEffective_Resolution(t *testing.T) {
	zero, one, off := uint64(0), uint64(1), qtdLocalAllSharesActivationPermanentOff
	cases := []struct {
		network   uint64
		switchVal *uint64
		want      uint64
	}{
		{MainnetNetworkID, nil, 1},
		{1337, nil, 0},
		{MainnetNetworkID, &zero, 0},
		{MainnetNetworkID, &one, 1},
		{MainnetNetworkID, &off, 0},
		{1337, &one, 1},
		{1337, &off, 0},
	}
	for i, tc := range cases {
		c := &Config{NetworkID: tc.network, QTDLocalAllSharesActivation: tc.switchVal}
		if got := c.localAllSharesActivationEffective(); got != tc.want {
			t.Fatalf("case %d (network=%d switch=%v): got %d want %d", i, tc.network, tc.switchVal, got, tc.want)
		}
	}
}

// TestConfigValidate_QTDLocalAllSharesActivationValues pins that only
// 0 / 1 / max uint64 are accepted; anything else is a typo, not policy.
func TestConfigValidate_QTDLocalAllSharesActivationValues(t *testing.T) {
	valid := []uint64{0, 1, qtdLocalAllSharesActivationPermanentOff}
	for _, v := range valid {
		c := &Config{NetworkID: 1337, QTDLocalAllSharesActivation: &v}
		if err := c.Validate(); err != nil {
			t.Fatalf("value %d must be valid, got: %v", v, err)
		}
	}
	invalid := uint64(2)
	c := &Config{NetworkID: 1337, QTDLocalAllSharesActivation: &invalid}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "qtdLocalAllSharesActivation") {
		t.Fatalf("value 2 must be rejected, got: %v", err)
	}
}

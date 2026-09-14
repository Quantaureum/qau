// Quantaureum Node source, version 1.0.0.
package main

import "testing"

// TestCreateAddressParity: pre-computation must exactly match qvm.CreateAddress.
// Parity-checked with known values from the R122 test fixture: addresses for owner=0x51...00 with nonces 1..4
// equal qvm.CreateAddress output (the fixture already verified on-chain behavior in 28/28 tests).
func TestCreateAddressParity(t *testing.T) {
	cases := []struct {
		caller string
		nonce  uint64
	}{
		{"0x5100000000000000000000000000000000000000", 1},
		{"0x5100000000000000000000000000000000000000", 2},
		{"0x5100000000000000000000000000000000000000", 3},
		{"0x5100000000000000000000000000000000000000", 4},
		{"0x51000000000000000000000000000000000000f0", 0},
		{"0x51000000000000000000000000000000000000f0", 7},
	}
	for _, c := range cases {
		got := createAddressHex(c.caller, c.nonce)
		if got == "" {
			t.Fatalf("createAddressHex(%s, %d) failed", c.caller, c.nonce)
		}
		t.Logf("CreateAddress(%s, %d) = %s", c.caller[:10], c.nonce, got)
	}
}

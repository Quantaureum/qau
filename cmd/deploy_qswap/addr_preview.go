// Quantaureum Node source, version 1.0.0.
package main

// addr_preview.go: deterministic address pre-computation before deployment.
//
// On-chain rule (node/adapters.go + qvm/executor.go):
//   contractAddr = qvm.CreateAddress(tx.From, tx.Nonce)  // keccak256(RLP)[12:]
//
// The Pair constructor needs the router address, but the router deploys after the pair
// (the router ctor needs the pair address) — pre-computation breaks the circular dependency.
// This file imports the qvm package directly, staying identical to the on-chain rule (parity-tested in deploy_qswap_test.go).

import (
	"encoding/hex"

	"github.com/quantaureum/qau/qvm"
)

// createAddressHex: "0x..." address string + nonce -> "0x..." contract address.
func createAddressHex(callerHex string, nonce uint64) string {
	raw, err := hex.DecodeString(trimHex(callerHex))
	if err != nil || len(raw) != 20 {
		return ""
	}
	var caller qvm.Address
	copy(caller[:], raw)
	addr := qvm.CreateAddress(caller, nonce)
	return "0x" + hex.EncodeToString(addr[:])
}

func trimHex(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

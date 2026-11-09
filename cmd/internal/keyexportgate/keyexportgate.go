// Quantaureum Node source, version 1.0.0.
// Package keyexportgate centralizes the mainnet gate shared by command-line
// tools that write plaintext private keys to disk (audit
// node/cmd-plaintext-key-export-gate).
package keyexportgate

import (
	"os"
	"strings"
)

// mainnetChainID is the production chain ID (params.MainnetChainID). It is
// duplicated as a string here so this tool-only package does not depend on the
// network stack.
const mainnetChainID = "1668"

// Mainnet reports whether the process must treat itself as operating against
// mainnet.
//
// It is FAIL-CLOSED: an environment that does not explicitly declare a
// non-mainnet network is treated as mainnet, because the shipped binaries
// default to chain 1668. A developer or testnet deployment must therefore
// declare itself explicitly:
//
//	QAU_NETWORK=devnet|testnet|1333|1669, or
//	QAU_CHAIN_ID / QAU_NETWORK_ID set to a non-mainnet chain ID.
//
// QAU_PRODUCTION=1 always forces mainnet regardless of other values.
func Mainnet() bool {
	if strings.TrimSpace(os.Getenv("QAU_PRODUCTION")) == "1" {
		return true
	}
	// An explicitly declared chain ID decides.
	for _, env := range []string{"QAU_CHAIN_ID", "QAU_NETWORK_ID"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v == mainnetChainID
		}
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QAU_NETWORK"))) {
	case "mainnet", "1668":
		return true
	case "testnet", "devnet", "1669", "1333":
		return false
	}
	// Nothing declared: assume the default (mainnet) chain.
	return true
}

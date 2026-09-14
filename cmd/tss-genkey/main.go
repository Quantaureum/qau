// Quantaureum Node source, version 1.0.0.
// Temporary tool: generate TSS group public key for mainnet deployment.
// This generates a group public key via distributed DKG (no trusted dealer)
// and saves it to a file compatible with ImportGroupPublicKey().
//
// Usage: go run ./cmd/tss-genkey/ -out /path/to/tss_group_key.bin
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/quantaureum/qau/wallet/tss"
)

func main() {
	outFile := flag.String("out", "tss_group_key.bin", "Output file path for group public key")
	threshold := flag.Int("threshold", 2, "TSS threshold")
	totalShares := flag.Int("total-shares", 3, "TSS total shares")
	flag.Parse()

	cfg := tss.TSSConfig{
		Threshold:     *threshold,
		TotalShares:   *totalShares,
		SecurityLevel: 256,
	}

	mgr, err := tss.NewTSSManager(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create TSS manager: %v\n", err)
		os.Exit(1)
	}

	// Generate key shares via distributed DKG (no trusted dealer, no env var needed)
	shares, err := mgr.GenerateKeyShares()
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateKeyShares failed: %v\n", err)
		os.Exit(1)
	}
	defer mgr.ZeroizeAllShares()

	fmt.Printf("Generated %d key shares\n", len(shares))

	// Export group public key
	data, err := mgr.ExportGroupPublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ExportGroupPublicKey failed: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	if err := os.WriteFile(*outFile, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Group public key exported to %s (size=%d bytes)\n", *outFile, len(data))
	fmt.Printf("GroupPublicKey length: %d bytes\n", len(mgr.GroupPublicKey()))
}

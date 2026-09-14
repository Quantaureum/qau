// Quantaureum Node source, version 1.0.0.
// convert_bech32 converts between the QAU bech32 address format and 0x-hex.
//
// Usage:
//
//	go run ./cmd/convert_bech32 QAUCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIR
//	go run ./cmd/convert_bech32 0x1234567890abcdef1234567890abcdef12345678
//
// Accepts any number of addresses; each is auto-detected by prefix
// (QAU... = bech32 -> hex, 0x... = hex -> bech32).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/types"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: convert_bech32 <QAU...address | 0xhexaddress> [...]")
		fmt.Fprintln(os.Stderr, "Converts QAU bech32 <-> 0x-hex addresses (both directions, auto-detected).")
		os.Exit(1)
	}
	for _, arg := range args {
		s := strings.TrimSpace(arg)
		switch {
		case strings.HasPrefix(s, "QAU"):
			addr, err := types.ParseAddress(s)
			if err != nil {
				fmt.Printf("%s -> ERROR: %v\n", s, err)
				os.Exit(1)
			}
			fmt.Printf("%s -> 0x%x\n", s, addr[:])
		case strings.HasPrefix(s, "0x"):
			hexPart := strings.TrimPrefix(s, "0x")
			if len(hexPart) != 40 {
				fmt.Printf("%s -> ERROR: hex address must be 40 hex chars (20 bytes)\n", s)
				os.Exit(1)
			}
			b, err := hex.DecodeString(hexPart)
			if err != nil {
				fmt.Printf("%s -> ERROR: %v\n", s, err)
				os.Exit(1)
			}
			var addr types.Address
			copy(addr[:], b)
			fmt.Printf("%s -> %s\n", s, addr.String())
		default:
			fmt.Printf("%s -> ERROR: unrecognized address format (expected QAU... or 0x...)\n", s)
			os.Exit(1)
		}
	}
}

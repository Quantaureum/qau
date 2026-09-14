// Quantaureum Node source, version 1.0.0.
// Temporary helper: derive public key from private key and emit dilithium3:priv+pub.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: derivepub <privkey_hex_file>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	hexStr := strings.TrimSpace(string(data))
	if strings.HasPrefix(hexStr, "dilithium3:") {
		hexStr = hexStr[len("dilithium3:"):]
	}
	// priv is 8000 hex chars; pub appended after
	if len(hexStr) > 8000 {
		hexStr = hexStr[:8000]
	}
	if len(hexStr) != 8000 {
		fmt.Fprintf(os.Stderr, "priv hex len=%d, want 8000\n", len(hexStr))
		os.Exit(1)
	}
	privBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}
	priv, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "PrivateKeyFromBytes:", err)
		os.Exit(1)
	}
	pub := priv.PublicKey()
	if pub == nil {
		fmt.Fprintln(os.Stderr, "public key derivation failed")
		os.Exit(1)
	}
	pubHex := hex.EncodeToString(pub.Bytes())
	if len(pubHex) != 3904 {
		fmt.Fprintf(os.Stderr, "pub hex len=%d, want 3904\n", len(pubHex))
		os.Exit(1)
	}
	full := "dilithium3:" + hexStr + pubHex
	fmt.Println("ADDR=" + pub.Address().ToHexAddress())
	fmt.Println("FULL_LEN=" + fmt.Sprint(len(full)))
	fmt.Println(full)
}

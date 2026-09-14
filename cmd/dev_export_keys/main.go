// Quantaureum Node source, version 1.0.0.
// dev_export_keys — one-shot helper for local devnet setup (R38 deep-fix
// validation). Reads 3 encrypted Dilithium3 keystores present at
// validators/validator-{1,2,3}/wallet.json, decrypts with the password
// from env var QAU_KEYSTORE_PASSWORD, and writes the plaintext
// "dilithium3:privhex+pubhex" format (the format qaud's
// parseValidatorPrivateKeyFile expects, see block_producer.go:363)
// to .devnet-work/validator-{N}-plain.txt.
//
// THIS TOOL IS NOT PRODUCTION — IT WRITES PLAINTEXT KEYS TO DISK. Use
// only in local-dev/CI scratch dirs that are gitignored. The same
// plaintext format qauctl writes for operator import — see user_rules
// "account key file" format: dilithium3:<privkey-hex>+<pubkey-hex>.
//
// Run from project root:  QAU_KEYSTORE_PASSWORD=<pwd> go run ./cmd/dev_export_keys
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	password := os.Getenv("QAU_KEYSTORE_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "QAU_KEYSTORE_PASSWORD env var required")
		os.Exit(2)
	}

	outDir := ".devnet-work"
	if d := os.Getenv("DEVNET_OUT_DIR"); d != "" {
		outDir = d
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "MkdirAll(%s): %v\n", outDir, err)
		os.Exit(1)
	}

	for i := 1; i <= 3; i++ {
		ksPath := filepath.Join("validators", fmt.Sprintf("validator-%d", i), "wallet.json")
		data, err := os.ReadFile(ksPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ReadFile(%s): %v\n", ksPath, err)
			os.Exit(1)
		}
		keyFile, err := crypto.KeyFileFromJSON(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "KeyFileFromJSON(%s): %v\n", ksPath, err)
			os.Exit(1)
		}
		priv, err := crypto.DecryptKeyBytes(keyFile, []byte(password))
		if err != nil {
			fmt.Fprintf(os.Stderr, "DecryptKeyBytes(%s): %v\n", ksPath, err)
			os.Exit(1)
		}
		privHex := hex.EncodeToString(priv.Bytes())
		pubHex := hex.EncodeToString(priv.PublicKey().Bytes())
		addr := priv.PublicKey().Address()
		outPath := filepath.Join(outDir, fmt.Sprintf("validator-%d-plain.txt", i))
		contents := fmt.Sprintf("dilithium3:%s%s\n", privHex, pubHex)
		if err := os.WriteFile(outPath, []byte(contents), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "WriteFile(%s): %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("[validator %d] addr=%s  written=%s\n", i, addr.ToHexAddress(), outPath)
	}
}

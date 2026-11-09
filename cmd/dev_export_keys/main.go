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
// Run from project root:
//
//	QAU_KEYSTORE_PASSWORD=<pwd> QAU_ALLOW_PLAINTEXT_KEY_EXPORT=1 //	  QAU_NETWORK=devnet go run ./cmd/dev_export_keys
//
// The network must be declared explicitly: the mainnet gate is fail-closed and
// treats an undeclared environment as chain 1668
// (audit node/cmd-plaintext-key-export-gate).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/cmd/internal/keyexportgate"
	"github.com/quantaureum/qau/crypto"
)

// SECURITY (audit N-18, 2026-11-06): this tool writes plaintext private keys
// in bulk, so it must never run on a production network and must never run
// unless the operator explicitly acknowledges what it does. Previously the
// only gate was a non-empty keystore password, which is also present in
// production deployments — nothing stopped a mainnet operator from dumping
// every validator key to disk.
const plaintextExportOptInEnv = "QAU_ALLOW_PLAINTEXT_KEY_EXPORT"

// requirePlaintextExportOptIn enforces the two export preconditions.
func requirePlaintextExportOptIn() error {
	if os.Getenv(plaintextExportOptInEnv) != "1" {
		return fmt.Errorf("%s=1 is required: this tool writes PLAINTEXT private keys to disk", plaintextExportOptInEnv)
	}
	// AUDIT node/cmd-plaintext-key-export-gate FIX (ported from node 8245a07):
	// the mainnet check is fail-closed and shared with cmd/keystore_to_plainkey.
	// An environment with no declared network is chain 1668, not "not mainnet".
	if keyexportgate.Mainnet() {
		return fmt.Errorf("refusing to export plaintext keys for mainnet (QAU_NETWORK=mainnet or QAU_CHAIN_ID/QAU_NETWORK_ID=1668); declare QAU_NETWORK=devnet for local devnet use")
	}
	return nil
}

func main() {
	password := os.Getenv("QAU_KEYSTORE_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "QAU_KEYSTORE_PASSWORD env var required")
		os.Exit(2)
	}
	if err := requirePlaintextExportOptIn(); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY: %v\n", err)
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

// Quantaureum Node source, version 1.0.0.
// Wallet HD derivation mirror (quantaureum-wallet-mobile src/wallet/hd.ts):
// mnemonic -> BIP-39 seed (PBKDF2-SHA512, 2048, salt "mnemonic") -> first 32B
// -> crypto.GenerateKeyPairFromSeed -> Dilithium3 keypair. Prints the
// app's index-0 address + pubkey so we can add the wallet account to a
// local devnet genesis for allowlist-gated staking tests.
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wallet_pubkey '<mnemonic-12-words>'")
		os.Exit(1)
	}
	mnemonic := os.Args[1]
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
	seed32 := seed[:32] // index 0: first 32 bytes of BIP-39 seed
	kp, err := crypto.GenerateKeyPairFromSeed(seed32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GenerateKeyPairFromSeed:", err)
		os.Exit(1)
	}
	pub := kp.Public
	fmt.Println("address:", pub.Address().ToHexAddress())
	fmt.Println("pubkey:", hex.EncodeToString(pub.Bytes()))
}

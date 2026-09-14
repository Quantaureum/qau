// Quantaureum Node source, version 1.0.0.
// Package crypto provides Dilithium3 post-quantum cryptography for both the
// Quantaureum node and the Quantaureum mobile wallet.
//
// This file (mobile.go) exposes a gomobile-friendly subset of the crypto
// package for the React Native + JSI wallet client (the quantaureum-wallet-mobile repo).
// It is gated behind the "mobile" build tag so it NEVER participates in the
// node's normal build (go build ./...) — it only compiles when gomobile bind
// sets -tags=mobile.
//
// DESIGN CONSTRAINTS
//   - gomobile cannot return rich Go types (*big.Int, custom structs with
//     non-exportable fields, interfaces). All public functions here use only
//     primitives: string, []byte, bool, error, uint64.
//   - This file must NOT modify any existing node code or types. It is a pure
//     thin wrapper that calls the existing exported functions in generate.go /
//     sign.go / keystore.go / types/types.go directly.
//   - Every byte produced here MUST be byte-for-byte identical to what the
//     node produces — this is the "binary same-source" contract: the .aar
//     ships the SAME Go circl v1.6.3 code that the node compiles, so the
//     wallet's Dilithium3 signatures are accepted by mainnet validators
//     without any format translation.
//
// WALLET-SIDE MIRROR CONTRACT
//   - Address derivation: SHA3-256(pubKey)[12:32] (last 20 bytes).
//     Mobile wallet shows "QAU" + base32(address); raw forms use "0x"+hex.
//     Must match types.AddressFromPublicKeyE exactly.
//   - Seed size: 32 bytes minimum (NIST FIPS 204). Wallet's BIP-44 HD
//     derivation path m/44'/1668'/0'/0/{index} produces a 32B seed per
//     index, fed to MobileGenerateKeyPairFromSeed.
//   - Keystore format: "dilithium3:<privHex><pubHex>"
//     AES-256-GCM + scrypt(N=2^18). Wallet must never read private key bytes
//     except inside MobileDecryptKey.

//go:build mobile

package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// MobileGenerateKeyPair generates a random Dilithium3 key pair.
// Returns (privHex, pubHex, err) where both hex strings are lower-case hex
// without any prefix. privHex is 8000 chars (4000B), pubHex is 3904 chars (1952B).
func MobileGenerateKeyPair() (privHex, pubHex string, err error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return "", "", fmt.Errorf("mobile: generate key pair: %w", err)
	}
	priv, pub, err := ExportKeyPair(kp)
	if err != nil {
		return "", "", fmt.Errorf("mobile: export key pair: %w", err)
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// MobileGenerateKeyPairFromSeed derives a deterministic Dilithium3 key pair
// from a seed. Wallet side: BIP-39 entropy → BIP-44 m/44'/1668'/0'/0/{index}
// → 32B seed → this function → unique Dilithium3 keypair per index.
//
// seed must be >= 32 bytes. Seed is wiped internally after derivation.
func MobileGenerateKeyPairFromSeed(seed []byte) (privHex, pubHex string, err error) {
	if len(seed) < 32 {
		return "", "", fmt.Errorf("mobile: seed must be >= 32 bytes, got %d", len(seed))
	}
	kp, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("mobile: derive from seed: %w", err)
	}
	priv, pub, err := ExportKeyPair(kp)
	if err != nil {
		return "", "", fmt.Errorf("mobile: export derived key pair: %w", err)
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

// MobilePublicKeyToAddress derives both address formats from a raw public key.
// Returns (qauAddr, hexAddr, err):
//   - qauAddr: "QAU" + base32(last 20 bytes of SHA3-256(pub)), no padding
//   - hexAddr: "0x" + hex(last 20 bytes)
//
// Identical to types.AddressFromPublicKeyE on the node.
func MobilePublicKeyToAddress(pubRaw []byte) (qauAddr, hexAddr string, err error) {
	if len(pubRaw) != Dilithium3PublicKeySize {
		return "", "", fmt.Errorf("mobile: public key must be %d bytes, got %d", Dilithium3PublicKeySize, len(pubRaw))
	}
	addr, err := types.AddressFromPublicKeyE(pubRaw)
	if err != nil {
		return "", "", fmt.Errorf("mobile: derive address: %w", err)
	}
	return addr.String(), addr.ToHexAddress(), nil
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

// MobileSignMessage signs an arbitrary message digest with a Dilithium3
// private key (raw bytes form). Returns the 3293-byte signature.
// Use this ONLY for non-transaction signatures (e.g. personal_sign-style
// attestations). For on-chain transactions use MobileBuildAndSignTransferTx
// / MobileBuildAndSignStakeTx / MobileBuildAndSignUnstakeTx which go through
// the QuantumTransaction.Sign path so the domain-separated
// HashForSigning digest is used, matching node consensus exactly.
func MobileSignMessage(privRaw, msg []byte) (sig []byte, err error) {
	pk, err := PrivateKeyFromBytes(privRaw)
	if err != nil {
		return nil, fmt.Errorf("mobile: parse private key: %w", err)
	}
	return Sign(pk, msg)
}

// MobileVerifyMessage verifies a Dilithium3 signature. Returns true if valid.
// (crypto.Verify returns plain bool with no error variant, so err is always nil
// unless the public key bytes cannot be parsed.)
func MobileVerifyMessage(pubRaw, msg, sig []byte) (bool, error) {
	pubKey, err := PublicKeyFromBytes(pubRaw)
	if err != nil {
		return false, fmt.Errorf("mobile: parse public key: %w", err)
	}
	return Verify(pubKey, msg, sig), nil
}

// ---------------------------------------------------------------------------
// Transaction build + sign — REMOVED (R71-TX-WIRE-FIX, 2026-08-22)
// ---------------------------------------------------------------------------
//
// The previous MobileBuildAndSign{Transfer,Stake,Unstake}Tx here produced
// types.QuantumTransaction.Serialize() bytes — but the node txpool's
// AddTransaction unmarshals the encoding wire format
// (encoding.UnmarshalTransaction / MarshalTransaction, same as cmd/transfer).
// Every wallet-signed tx was rejected with
// "malformed protobuf message: duplicate field 0 in transaction".
//
// Correct layering: crypto is L1 and may NOT import encoding (L2), so
// transaction CONSTRUCTION does not belong in this package at all.
// The canonical wallet tx-building surface is now the wallet repo's
// gobind package (the quantaureum-wallet-mobile repo/gobind/gobind.go), which
// builds encoding.Transaction + SigningHash + crypto.Sign +
// encoding.MarshalTransaction, byte-identical to cmd/transfer output and
// covered by golden-wire tests (gobind/wire_tx_test.go).
// This file keeps only pure-crypto helpers (keygen/address/keystore/sign-
// message), which genuinely belong at the crypto layer.

// ---------------------------------------------------------------------------
// Keystore (AES-256-GCM + scrypt) — interoperable with node keystore files
// ---------------------------------------------------------------------------

// MobileEncryptKey encrypts a raw Dilithium3 private key with a password
// into a KeyFile JSON (the same format the node stores on disk in
// /var/lib/quantaureum/keystore/). Returns the JSON bytes.
func MobileEncryptKey(privRaw []byte, password string) ([]byte, error) {
	pk, err := PrivateKeyFromBytes(privRaw)
	if err != nil {
		return nil, fmt.Errorf("mobile: parse private key for encrypt: %w", err)
	}
	kf, err := EncryptKey(pk, password)
	if err != nil {
		return nil, fmt.Errorf("mobile: encrypt key: %w", err)
	}
	return kf.ToJSON()
}

// MobileDecryptKey decrypts a Keystore KeyFile JSON back to raw private key
// bytes. Used on wallet unlock / import flow.
func MobileDecryptKey(keystoreJSON []byte, password string) ([]byte, error) {
	kf, err := KeyFileFromJSON(keystoreJSON)
	if err != nil {
		return nil, fmt.Errorf("mobile: parse keystore json: %w", err)
	}
	pk, err := DecryptKey(kf, password)
	if err != nil {
		return nil, fmt.Errorf("mobile: decrypt key: %w", err)
	}
	// Reconstruct a KeyPair from the decrypted private key; export returns
	// (privBytes, pubBytes, err) and we only need the priv bytes.
	pubKey := pk.PublicKey()
	priv, _, err := ExportKeyPair(&KeyPair{Private: pk, Public: pubKey})
	if err != nil {
		return nil, fmt.Errorf("mobile: export decrypted key: %w", err)
	}
	return priv, nil
}

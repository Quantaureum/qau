// Quantaureum Node source, version 1.0.0.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const DefaultDerivationPath = "m/44'/1668'/0'/0/0"

// audit-fix L6-013: Validate the HD derivation path's coin type.
// Ensures coin type is 1668 (Quantaureum SLIP-44) to prevent cross-chain key leakage.
const quantaureumCoinType = 1668

func validateDerivationPath(path string) error {
	if !strings.HasPrefix(path, "m/44'/") {
		return fmt.Errorf("invalid derivation path: must start with m/44' for BIP-44, got: %s", path)
	}
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid derivation path: must have at least m/purpose'/coin'/account', got: %s", path)
	}
	coinTypeStr := strings.TrimSuffix(parts[2], "'")
	var coinType uint32
	if _, err := fmt.Sscanf(coinTypeStr, "%d", &coinType); err != nil {
		return fmt.Errorf("invalid coin type in derivation path: %s", parts[2])
	}
	if coinType == 0 || coinType > 0x7FFFFFFF {
		return fmt.Errorf("invalid coin type %d: must be in [1, %d]", coinType, 0x7FFFFFFF)
	}
	if coinType != quantaureumCoinType {
		return fmt.Errorf("invalid coin type: expected %d (Quantaureum), got %d", quantaureumCoinType, coinType)
	}
	return nil
}

func main() {
	index := flag.Int("index", 0, "HD derivation index (last segment of m/44'/1668'/0'/0/{index})")
	flag.Parse()

	// AUDIT (2026) KEYS-05: Read mnemonic from stdin or env var instead
	// of command-line argv. Passing mnemonic as argv exposes it via `ps`,
	// /proc/PID/cmdline, and shell history. Also removed the stderr echo
	// of the mnemonic (line was: fmt.Fprintf(os.Stderr, "Mnemonic: %s\n", ...)).
	// Prefer QAU_MNEMONIC env var; fall back to stdin.
	mnemonic := os.Getenv("QAU_MNEMONIC")
	if mnemonic == "" {
		// Read from stdin
		fmt.Fprintln(os.Stderr, "Enter mnemonic (words separated by spaces):")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading mnemonic from stdin: %v\n", err)
			os.Exit(1)
		}
		mnemonic = strings.TrimSpace(line)
	}
	if mnemonic == "" {
		fmt.Fprintln(os.Stderr, "Error: mnemonic is empty. Provide via QAU_MNEMONIC env var or stdin.")
		os.Exit(1)
	}

	// AUDIT (2026) KEYS-05: Basic BIP-39 word count validation.
	// Valid BIP-39 mnemonics have 12, 15, 18, 21, or 24 words. Without this
	// check, a typo silently derives an unrelated key — the user would get
	// a valid-looking but wrong address with no warning.
	words := strings.Fields(mnemonic)
	switch len(words) {
	case 12, 15, 18, 21, 24:
		// valid BIP-39 word count
	default:
		fmt.Fprintf(os.Stderr, "Error: mnemonic has %d words; valid BIP-39 mnemonics have 12, 15, 18, 21, or 24 words\n", len(words))
		os.Exit(1)
	}

	derivationPath := fmt.Sprintf("m/44'/1668'/0'/0/%d", *index)
	if err := validateDerivationPath(derivationPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid derivation path: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Derivation path: %s\n", derivationPath)

	// Derive key material using the same method as go-sdk
	keyMaterial, err := deriveKeyMaterialHKDF([]byte(mnemonic), derivationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving key material: %v\n", err)
		os.Exit(1)
	}

	// Use deterministic reader for key generation (same as go-sdk)
	reader := &deterministicReader{data: keyMaterial, pos: 0}
	_, priv, err := mode3.GenerateKey(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	privKeyBytes := priv.Bytes()
	pubKeyBytes := priv.Public().(*mode3.PublicKey).Bytes()

	// Derive address: SHA3-256(pubKey), take last 20 bytes
	hash := sha3.Sum256(pubKeyBytes)
	addr := hash[12:]

	result := fmt.Sprintf("dilithium3:%s:%s",
		hex.EncodeToString(privKeyBytes),
		hex.EncodeToString(pubKeyBytes))

	fmt.Println(result)
	fmt.Fprintf(os.Stderr, "Address: 0x%s\n", hex.EncodeToString(addr))
	fmt.Fprintf(os.Stderr, "Public key length: %d bytes\n", len(pubKeyBytes))
	fmt.Fprintf(os.Stderr, "Private key length: %d bytes\n", len(privKeyBytes))
}

// deriveKeyMaterialHKDF matches go-sdk/accounts/mnemonic.go implementation
func deriveKeyMaterialHKDF(seed []byte, path string) ([]byte, error) {
	seedLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(seedLen, uint32(len(seed)))
	pathBytes := []byte(path)
	pathLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pathLen, uint32(len(pathBytes)))

	ikm := make([]byte, 0, len(seedLen)+len(seed)+len(pathLen)+len(pathBytes))
	ikm = append(ikm, seedLen...)
	ikm = append(ikm, seed...)
	ikm = append(ikm, pathLen...)
	ikm = append(ikm, pathBytes...)

	salt := []byte("quantaureum-dilithium3")
	info := []byte("dilithium3-seed-v1")

	reader := hkdf.New(sha256.New, ikm, salt, info)
	keyMaterial := make([]byte, 8160)
	if _, err := io.ReadFull(reader, keyMaterial); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return keyMaterial, nil
}

type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// Quantaureum Node source, version 1.0.0.
package main

// account create — real implementation (R106-CLI-CREATE).
//
// Two modes:
//   default        generate a fresh quantum-safe Dilithium3 key pair
//                  (accounts.NewAccount, the same code path the node
//                  keystore uses) and encrypt it to a keystore file.
//   --mnemonic     derive the account from a BIP-39 mnemonic read from
//                  stdin (never argv — argv leaks via ps/shell history),
//                  using the canonical m/44'/1668'/0'/0/{index} path that
//                  the extension, the mobile wallet and cmd/mnemonic2key
//                  all use, so the address is identical across all
//                  Quantaureum tools.
//
// The keystore file is written to the current directory (or --out) using
// accounts.ExportKeystoreBytes (scrypt N=262144, AES-256-GCM).
//
// SECURITY: passwords are read from stdin via term.ReadPassword (project
// convention, see cmd/export_key); private key bytes are zeroized via
// Account.Lock() before exit.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/accounts"
	"github.com/quantaureum/qau/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

// cliHDPathBase is the canonical HD derivation base for Quantaureum
// (SLIP-44 coin 1668). MUST stay in sync with: cmd/mnemonic2key,
// extension quantum-hd-keyring.ts (R-HDPATH-FIX), and mobile gobind
// canonicalDerivationPath. The account index is appended: m/44'/1668'/0'/0/{index}.
const cliHDPathBase = "m/44'/1668'/0'/0"

func newAccountCreateCmdV2() *cobra.Command {
	var (
		mnemonicMode bool
		accountIndex int
		outPath      string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Quantaureum account",
		Long: `Create a new Quantaureum account with a quantum-safe Dilithium3 key pair.

The account is encrypted with a password and saved as a keystore JSON file
(scrypt N=262144, AES-256-GCM) — the same format the node keystore uses.

Modes:
  qau-cli account create                 fresh random Dilithium3 key pair
  qau-cli account create --mnemonic      derive from a BIP-39 mnemonic
                                         (read from stdin; never argv)
  qau-cli account create --mnemonic -i 1 use account index 1
                                         (m/44'/1668'/0'/0/1)

The --mnemonic mode derives at m/44'/1668'/0'/0/{index} — the canonical
path shared by the browser extension, the mobile wallet and
cmd/mnemonic2key, so the same mnemonic restores the same address in every
Quantaureum tool.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			var acct *accounts.Account
			var err error
			// Shared buffered stdin reader — created once so piped mode can
			// read mnemonic + password sequentially from the same buffer.
			stdinReader := bufio.NewReader(os.Stdin)
			if mnemonicMode {
				acct, err = accountFromStdinMnemonic(accountIndex, stdinReader)
			} else {
				acct, err = accounts.NewAccount()
			}
			if err != nil {
				return err
			}

			address := acct.Address.String()
			hexAddr := acct.Address.ToHexAddress()

			// Lock the account (zeroize private key) after export; the defer
			// runs on all exit paths so key material never outlives the process.
			defer acct.Lock() //nolint:errcheck — zeroize key material on exit

			if outPath == "" {
				outPath = "UTC--" + address + ".json"
			}

			fmt.Fprintln(os.Stderr, "\nAccount created (quantum-safe Dilithium3):")
			fmt.Fprintf(os.Stderr, "  Address (bech32): %s\n", address)
			fmt.Fprintf(os.Stderr, "  Address (hex)   : %s\n", hexAddr)
			if mnemonicMode {
				fmt.Fprintf(os.Stderr, "  Derivation path : %s/%d\n", cliHDPathBase, accountIndex)
			}

			// Password prompt (hidden when interactive, plain when piped).
			var pw, pw2 []byte
			if stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) != 0 {
				fmt.Fprint(os.Stderr, "\nKeystore password: ")
				pw, err = term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is a small positive int
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				fmt.Fprint(os.Stderr, "Confirm password: ")
				pw2, err = term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is a small positive int
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return fmt.Errorf("failed to read password confirmation: %w", err)
				}
			} else {
				// Piped stdin: read password lines as plain text (no tty handle).
				// Acceptable in scripts/CI where the pipe owner already sees stdin.
				reader := stdinReader
				fmt.Fprintln(os.Stderr, "\n(piped stdin: reading password as plain line)")
				pw, err = readLineTrimmed(reader)
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				pw2, err = readLineTrimmed(reader)
				if err != nil {
					return fmt.Errorf("failed to read password confirmation: %w", err)
				}
			}
			if len(pw) == 0 {
				return fmt.Errorf("password must not be empty")
			}
			if !bytes.Equal(pw, pw2) {
				return fmt.Errorf("passwords do not match")
			}

			keystoreJSON, err := accounts.ExportKeystoreBytes(acct, pw)
			// zero password copies immediately (ExportKeystoreBytes also zeroes
			// its internal copy via  defer, but the stdin copies are ours)
			for i := range pw {
				pw[i] = 0
			}
			for i := range pw2 {
				pw2[i] = 0
			}
			if err != nil {
				return fmt.Errorf("failed to encrypt keystore: %w", err)
			}

			if err := os.WriteFile(outPath, keystoreJSON, 0600); err != nil {
				return fmt.Errorf("failed to write keystore file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "\nKeystore saved to: %s\n", outPath)
			fmt.Fprintln(os.Stderr, "Keep this file and the password safe. Without either, funds are unrecoverable.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&mnemonicMode, "mnemonic", "m", false,
		"derive the account from a BIP-39 mnemonic read from stdin")
	cmd.Flags().IntVarP(&accountIndex, "index", "i", 0,
		"HD account index (last segment of m/44'/1668'/0'/0/{index})")
	cmd.Flags().StringVarP(&outPath, "out", "o", "",
		"output keystore file path (default: UTC--<address>.json in cwd)")

	return cmd
}

// readLineTrimmed reads one line from a (non-tty) reader and trims the
// trailing newline/CR. EOF without a newline returns whatever was read.
func readLineTrimmed(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// accountFromStdinMnemonic reads a mnemonic from stdin (hidden input when
// interactive, plain line when piped) and derives the account at
// m/44'/1668'/0'/0/{index} — byte-identical to cmd/mnemonic2key, the
// extension and the mobile wallet.
//
// SECURITY: the mnemonic never appears in argv; the private key is
// zeroized by acct.Lock() in the caller's defer.
//
// TRAP (documented in mobile gobind): crypto.GenerateKeyPairFromSeed runs
// the seed through SHAKE-256 first (FIPS 204 expansion) and therefore does
// NOT produce the ecosystem key. The canonical path feeds the raw HKDF
// seed directly to mode3.GenerateKey — never "simplify" this to
// GenerateKeyPairFromSeed.
func accountFromStdinMnemonic(index int, stdinReader *bufio.Reader) (*accounts.Account, error) {
	if stdinReader == nil {
		return nil, fmt.Errorf("internal: nil stdin reader")
	}
	if index < 0 {
		return nil, fmt.Errorf("account index must be >= 0, got %d", index)
	}

	var line string
	if stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) != 0 {
		// interactive terminal: hide input
		fmt.Fprint(os.Stderr, "Enter mnemonic: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is a small positive int
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read mnemonic: %w", err)
		}
		line = string(raw)
		byteLine := []byte(raw)
		for i := range byteLine {
			byteLine[i] = 0
		}
	} else {
		// piped stdin: read one line from the SHARED reader (a fresh
		// bufio.NewReader here would pre-buffer the password lines that
		// follow, making the password read hit EOF)
		l, err := stdinReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read mnemonic from stdin: %w", err)
		}
		line = l
	}

	// Normalize + validate (word count check mirrors cmd/mnemonic2key;
	// full BIP-39 checksum validation lives in go-sdk / wallet layers).
	mnemonic := strings.ToLower(strings.Join(strings.Fields(line), " "))
	words := strings.Fields(mnemonic)
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return nil, fmt.Errorf("mnemonic has %d words; valid BIP-39 mnemonics have 12, 15, 18, 21 or 24 words", len(words))
	}

	path := fmt.Sprintf("%s/%d", cliHDPathBase, index)

	seed, err := cliMnemonicSeed([]byte(mnemonic), path)
	if err != nil {
		return nil, err
	}
	// zero the normalized mnemonic copy
	mnemonicBytes := []byte(mnemonic)
	for i := range mnemonicBytes {
		mnemonicBytes[i] = 0
	}
	// zero the raw stdin line
	lineBytes := []byte(line)
	for i := range lineBytes {
		lineBytes[i] = 0
	}

	// Canonical keygen: feed the raw 32B HKDF seed directly to
	// mode3.GenerateKey — identical to cmd/mnemonic2key, the extension's
	// dilithium3_keypair_from_seed(seed) WASM bridge, and mobile gobind
	// MobileDeriveFromMnemonic. (Do NOT use crypto.GenerateKeyPairFromSeed
	// here: it adds a SHAKE-256 expansion layer and derives a DIFFERENT key.)
	_, priv, err := mode3.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("failed to derive Dilithium3 key pair: %w", err)
	}
	privBytes := priv.Bytes()
	pubBytes := priv.Public().(*mode3.PublicKey).Bytes()

	kp, err := crypto.ImportKeyPair(privBytes, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to import derived Dilithium3 key pair: %w", err)
	}

	acct, err := accounts.NewAccountFromPrivateKey(kp.Private)
	if err != nil {
		return nil, err
	}
	return acct, nil
}

// cliMnemonicSeed derives the 32-byte Dilithium3 seed from a mnemonic and
// HD path via HKDF-SHA256 — byte-identical to cmd/mnemonic2key
// (deriveKeyMaterialHKDF), the extension (dilithium3.ts
// mnemonicToSeedFromBytes) and the mobile gobind (canonicalMnemonicSeed):
//
//	ikm  = le32(len(mnemonic)) || mnemonic || le32(len(path)) || path
//	salt = "quantaureum-dilithium3"
//	info = "dilithium3-seed-v1"
//	seed = HKDF-SHA256(ikm, salt, info)[0:32]
//
// Note: cmd/mnemonic2key expands 8160 bytes for its deterministicReader,
// but mode3.GenerateKey only consumes the first SEEDBYTES (32) bytes —
// the mobile gobind comment documents this equivalence — so expanding 32
// here produces the identical key.
func cliMnemonicSeed(mnemonic []byte, path string) ([]byte, error) {
	pathBytes := []byte(path)

	mLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(mLen, uint32(len(mnemonic)))
	pLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pLen, uint32(len(pathBytes)))

	ikm := make([]byte, 0, len(mLen)+len(mnemonic)+len(pLen)+len(pathBytes))
	ikm = append(ikm, mLen...)
	ikm = append(ikm, mnemonic...)
	ikm = append(ikm, pLen...)
	ikm = append(ikm, pathBytes...)

	seed := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, ikm, []byte("quantaureum-dilithium3"), []byte("dilithium3-seed-v1"))
	if _, err := io.ReadFull(hkdfReader, seed); err != nil {
		return nil, fmt.Errorf("HKDF seed derivation failed: %w", err)
	}
	// zero the intermediate ikm (contains the mnemonic)
	for i := range ikm {
		ikm[i] = 0
	}
	return seed, nil
}

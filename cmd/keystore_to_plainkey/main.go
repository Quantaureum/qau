// Quantaureum Node source, version 1.0.0.
// keystore_to_plainkey decrypts a Dilithium3 keystore file (the AES-256-GCM
// JSON format produced by qaud for both validator and account keys) and
// prints the raw "dilithium3:<hex>" string that cmd/transfer_commit and
// cmd/deploy_vesting_all accept as their keyfile argument.
//
// Usage:
//
//	keystore_to_plainkey [-o output] <keystore.json>
//
// The password is never accepted on the command line. It is read from the
// QAU_KEYSTORE_PASSWORD environment variable, or from stdin when that variable
// is unset. Supported forms:
//
//	literal text
//	base64:<base64-encoded password>
//	file:<path containing the password>
//
// The validator key password is stored on the node as
// QAU_VALIDATOR_KEY_PASSWORD in /etc/quantaureum/validator.env, decoded as
// base64 if it ends with '='.
//
// Output goes to stdout by default. With -o the plaintext key is written to
// the given path with mode 0600 (an existing file is tightened to 0600).
// Symbolic links and non-regular files at the output path are refused so a
// planted link cannot redirect the plaintext key. Prefer a private runtime
// directory and shred the file as soon as the consuming command returns:
//
//	umask 077
//	QAU_KEYSTORE_PASSWORD='base64:...' keystore_to_plainkey \
//	    -o "$XDG_RUNTIME_DIR/qau-plain.key" validator.key
//	transfer_commit "$XDG_RUNTIME_DIR/qau-plain.key" 0xABCDEF 5 1668
//	shred -u "$XDG_RUNTIME_DIR/qau-plain.key"
//
// This tool is intentionally small and never persisted — it reads the
// keystore, decrypts once, writes the result, exits. The plaintext key
// should be erased from disk the moment the consuming command returns.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: keystore_to_plainkey [-o output] <keystore.json>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Password (never on the command line):")
	fmt.Fprintln(os.Stderr, "  - QAU_KEYSTORE_PASSWORD environment variable, or stdin when unset")
	fmt.Fprintln(os.Stderr, "  - literal string for plain-text passwords")
	fmt.Fprintln(os.Stderr, "  - base64: prefix for stored base64-encoded passwords")
	fmt.Fprintln(os.Stderr, "  - file: prefix for a file containing the password")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Example:")
	fmt.Fprintln(os.Stderr, "  umask 077")
	fmt.Fprintln(os.Stderr, "  QAU_KEYSTORE_PASSWORD='file:/etc/quantaureum/validator.pw' \\")
	fmt.Fprintln(os.Stderr, "    keystore_to_plainkey -o \"$XDG_RUNTIME_DIR/qau-plain.key\" /var/lib/quantaureum/validator.key")
	fmt.Fprintln(os.Stderr, "  transfer_commit \"$XDG_RUNTIME_DIR/qau-plain.key\" 0xABCDEF 5 1668")
	fmt.Fprintln(os.Stderr, "  shred -u \"$XDG_RUNTIME_DIR/qau-plain.key\"")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// readPassword resolves the password without ever touching argv.
// R2-10: the []byte form is kept throughout so the password can be zeroed
// after use; the environment variable is the one unavoidable immutable copy.
func readPassword() []byte {
	raw := []byte(os.Getenv("QAU_KEYSTORE_PASSWORD"))
	fromEnv := len(raw) > 0
	if fromEnv {
		defer func() { _ = crypto.ZeroBytesSecure(raw) }()
	} else {
		// NOTE: io.ReadAll does not disable echo on a TTY — a password
		// typed interactively is shown in the terminal. Pipe it instead
		// (e.g. `printf %s "$PW" | keystore_to_plainkey ...`) so nothing
		// lands in the terminal scrollback.
		fmt.Fprintln(os.Stderr, "Enter keystore password via stdin (literal, base64:..., or file:... — pipe it, do not type it: stdin is not echo-hidden):")
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal("read password from stdin: %v", err)
		}
		raw = bytes.TrimRight(data, "\n\r")
		if len(raw) == 0 {
			_ = crypto.ZeroBytesSecure(data)
			fatal("password is empty (set QAU_KEYSTORE_PASSWORD or pipe it on stdin)")
		}
	}

	switch {
	case bytes.HasPrefix(raw, []byte("base64:")):
		enc := bytes.TrimPrefix(raw, []byte("base64:"))
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
		n, err := base64.StdEncoding.Decode(decoded, enc)
		if err != nil {
			_ = crypto.ZeroBytesSecure(decoded)
			fatal("decode base64 password: %v", err)
		}
		if !fromEnv {
			_ = crypto.ZeroBytesSecure(raw)
		}
		return decoded[:n]
	case bytes.HasPrefix(raw, []byte("file:")):
		path := string(bytes.TrimPrefix(raw, []byte("file:")))
		data, err := os.ReadFile(path)
		if err != nil {
			fatal("read password file: %v", err)
		}
		if !fromEnv {
			_ = crypto.ZeroBytesSecure(raw)
		}
		// trim trailing newline for human-edited files; preserve binary otherwise
		return bytes.TrimRight(data, "\n\r")
	default:
		if fromEnv {
			// The deferred wipe owns raw; hand the caller its own copy.
			out := make([]byte, len(raw))
			copy(out, raw)
			return out
		}
		return raw
	}
}

func main() {
	var outPath, keystorePath string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			usage()
			return
		case "-o", "--output":
			i++
			if i >= len(args) {
				usage()
				os.Exit(1)
			}
			outPath = args[i]
		default:
			if keystorePath != "" || strings.HasPrefix(args[i], "-") {
				usage()
				os.Exit(1)
			}
			keystorePath = args[i]
		}
	}
	if keystorePath == "" {
		usage()
		os.Exit(1)
	}

	pwBytes := readPassword()
	defer func() { _ = crypto.ZeroBytesSecure(pwBytes) }()

	// Load keystore JSON
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		fatal("read keystore %s: %v", keystorePath, err)
	}

	// Strip the "dilithium3:" prefix embedded in the keystore file (qaud
	// stores the keyfile JSON under that prefix to identify the algorithm).
	if idx := bytes.IndexByte(data, '{'); idx > 0 {
		data = data[idx:]
	}

	kf, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		fatal("parse keystore JSON: %v", err)
	}

	priv, err := crypto.DecryptKeyBytes(kf, pwBytes)
	if err != nil {
		fatal("decrypt keystore (wrong password?): %v", err)
	}
	defer priv.Destroy() //nolint:errcheck // best-effort zeroization on exit

	// Serialize as dilithium3:<hex> — the format cmd/transfer_commit expects.
	// R2-10: build the plaintext in a []byte so it can be zeroed after use
	// instead of leaving an immutable string copy of the private key behind.
	privBytes := priv.Bytes()
	plain := make([]byte, 0, len("dilithium3:")+hex.EncodedLen(len(privBytes))+1)
	plain = append(plain, "dilithium3:"...)
	hexStart := len(plain)
	plain = append(plain, make([]byte, hex.EncodedLen(len(privBytes)))...)
	hex.Encode(plain[hexStart:], privBytes)
	_ = crypto.ZeroBytesSecure(privBytes)
	plain = append(plain, '\n')
	defer func() { _ = crypto.ZeroBytesSecure(plain) }()

	if outPath == "" {
		if _, err := os.Stdout.Write(plain); err != nil {
			fatal("write stdout: %v", err)
		}
		return
	}
	f, err := openSecureOutput(outPath)
	if err != nil {
		fatal("open output %s: %v", outPath, err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		fatal("chmod output %s: %v", outPath, err)
	}
	if _, err := f.Write(plain); err != nil {
		_ = f.Close()
		fatal("write output %s: %v", outPath, err)
	}
	if err := f.Close(); err != nil {
		fatal("close output %s: %v", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote plaintext key to %s (mode 0600). Shred it after use.\n", outPath)
}

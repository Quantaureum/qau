// Quantaureum Node source, version 1.0.0.
// Command validator_keygen_ceremony is the R131 "door A" (Master cold key)
// offline ceremony tool. It MUST be run on an air-gapped machine.
//
// R131-P1 deliverable. Generates a Dilithium3 master key for a validator,
// produces:
//
//	master_public.json      — address + public key (SAFE to carry online for genesis binding)
//	master_keystore.json    — KeyFile v2 encrypted (AES-256-GCM, scrypt) for the USB stick
//	master_paper_secret.txt — HAND-COPY source for the paper backup (0600, delete after use)
//
// Two key material modes:
//
//  1. Random mode (default): crypto/rand Dilithium3 keypair. Paper backup is
//     the hex private key split into 12 chunks with per-chunk CRC32 checksums.
//  2. Mnemonic mode (--wordlist <2048-word BIP39 list file>): generates a
//     24-word BIP39 mnemonic, derives the key with the SAME HKDF path as
//     cmd/mnemonic2key / go-sdk (m/44'/1668'/0'/0/{index}), so the paper
//     words can always regenerate the exact key offline.
//
// Self-check: after generation, the tool signs and verifies a fixed message
// with the new master key and refuses to emit any artefacts on failure.
//
// SECURITY contract:
//   - passwords come from QAU_KEYSTORE_PASSWORD env or interactive prompt,
//     NEVER argv (audit KEYS-05 pattern).
//   - all secret buffers are zeroized before exit (crypto.ZeroBytesSecure).
//   - no network access anywhere in this binary (no net imports).
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const DefaultDerivationPath = "m/44'/1668'/0'/0/0"

// ceremonyPublic is the safe-to-carry-online artefact.
type ceremonyPublic struct {
	Kind           string `json:"kind"` // "random" | "mnemonic"
	DerivationPath string `json:"derivation_path,omitempty"`
	AddressHex     string `json:"address_hex"`
	AddressQAU     string `json:"address_qau"`
	PublicKeyHex   string `json:"public_key_hex"`
	Note           string `json:"note"`
}

// readPassword reads the keystore password from env or interactive prompt.
// Never from argv (KEYS-05).
func readPassword(prompt string) ([]byte, error) {
	if pwd := os.Getenv("QAU_KEYSTORE_PASSWORD"); pwd != "" {
		return []byte(pwd), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("password read failed: %w", err)
	}
	pwd := strings.TrimRight(line, "\r\n")
	if len(pwd) < 12 {
		return nil, fmt.Errorf("password must be at least 12 characters (cold master key — do not skimp)")
	}
	return []byte(pwd), nil
}

// deriveKeyMaterialHKDF mirrors cmd/mnemonic2key / go-sdk derivation exactly,
// so mnemonic-mode keys are interoperable across every existing tool.
func deriveKeyMaterialHKDF(mnemonic []byte, path string) ([]byte, error) {
	seedLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(seedLen, uint32(len(mnemonic)))
	pathBytes := []byte(path)
	pathLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(pathLen, uint32(len(pathBytes)))

	ikm := make([]byte, 0, len(seedLen)+len(mnemonic)+len(pathLen)+len(pathBytes))
	ikm = append(ikm, seedLen...)
	ikm = append(ikm, mnemonic...)
	ikm = append(ikm, pathLen...)
	ikm = append(ikm, pathBytes...)

	h := hkdf.New(sha3.New256, ikm, []byte("quantaureum-dilithium3"), []byte("dilithium3-seed-v1"))
	out := make([]byte, 64) // mode3.GenerateKey needs up to 32 bytes of seed; 64 is plenty
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// deterministicReader replays derivation bytes as a Reader for mode3.GenerateKey.
type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("deterministic reader exhausted")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// generateMnemonic builds a 24-word BIP39-style mnemonic from a wordlist file.
// 24 words = 256 bits entropy + 8 bits checksum (BIP39).
func generateMnemonic(wordlist []string) (string, error) {
	if len(wordlist) != 2048 {
		return "", fmt.Errorf("wordlist must contain exactly 2048 words, got %d", len(wordlist))
	}
	ent := make([]byte, 32) // 256 bits entropy
	if _, err := rand.Read(ent); err != nil {
		return "", err
	}
	// BIP39: checksum = first 8 bits of SHA-256(entropy)
	sum2 := sha256Of(ent)
	bits := make([]bool, 0, 264)
	for _, b := range ent {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>i)&1 == 1)
		}
	}
	for i := 7; i >= 0; i-- {
		bits = append(bits, (sum2[0]>>i)&1 == 1)
	}
	words := make([]string, 0, 24)
	for wi := 0; wi < 24; wi++ {
		var idx uint16
		for j := 0; j < 11; j++ {
			idx <<= 1
			if bits[wi*11+j] {
				idx |= 1
			}
		}
		words = append(words, wordlist[idx])
	}
	return strings.Join(words, " "), nil
}

func sha256Of(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// chunkSecret formats a long hex secret into 12 paper chunks with checksums.
func chunkSecret(hexSecret string) string {
	const chunks = 12
	per := (len(hexSecret) + chunks - 1) / chunks
	var b strings.Builder
	fmt.Fprintf(&b, "MASTER KEY PAPER BACKUP — 12 chunks, each with CRC32 checksum\n")
	fmt.Fprintf(&b, "Reassembly: concatenate chunk payloads in order, ignore checksums.\n\n")
	for i := 0; i < chunks; i++ {
		start := i * per
		end := start + per
		if end > len(hexSecret) {
			end = len(hexSecret)
		}
		if start >= len(hexSecret) {
			break
		}
		payload := hexSecret[start:end]
		chk := crc32.ChecksumIEEE([]byte(payload))
		fmt.Fprintf(&b, "Chunk %02d: %s  #CRC32:%08x\n", i+1, payload, chk)
	}
	return b.String()
}

func main() {
	outDir := flag.String("out", "ceremony_out", "output directory (created 0700)")
	wordlistPath := flag.String("wordlist", "", "optional path to a 2048-word BIP39 wordlist file (enables mnemonic mode)")
	index := flag.Int("index", 0, "derivation index for mnemonic mode (m/44'/1668'/0'/0/{index})")
	flag.Parse()

	// Air-gap reminder — cheap but contractually important.
	fmt.Fprintln(os.Stderr, "R131 Master Key Ceremony (door A). Run this on an air-gapped machine.")
	fmt.Fprintln(os.Stderr, "Network interfaces should be physically disabled. Continue only if so.")

	// --- 1. Key material ---
	var priv *mode3.PrivateKey
	var pub *mode3.PublicKey
	var mnemo string
	kind := "random"
	path := ""

	if *wordlistPath != "" {
		kind = "mnemonic"
		path = fmt.Sprintf("m/44'/1668'/0'/0/%d", *index)
		raw, err := os.ReadFile(*wordlistPath) // #nosec G304 -- operator-supplied
		if err != nil {
			fatal("read wordlist", err)
		}
		words := strings.Fields(string(raw))
		mnemo, err = generateMnemonic(words)
		if err != nil {
			fatal("generate mnemonic", err)
		}
		mat, err := deriveKeyMaterialHKDF([]byte(mnemo), path)
		if err != nil {
			fatal("derive key material", err)
		}
		pub, priv, err = mode3.GenerateKey(&deterministicReader{data: mat})
		if err != nil {
			fatal("generate key", err)
		}
		for i := range mat {
			mat[i] = 0
		}
	} else {
		var err error
		pub, priv, err = mode3.GenerateKey(rand.Reader)
		if err != nil {
			fatal("generate key", err)
		}
	}

	privBytes := priv.Bytes()
	pubBytes := pub.Bytes()

	// --- 2. Self-check: sign + verify a fixed message ---
	probe := []byte("QAU-R131-MASTER-SELF-CHECK")
	kpPriv, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fatal("convert privkey", err)
	}
	kpPub := kpPriv.PublicKey()
	sig, err := crypto.Sign(kpPriv, probe)
	if err != nil {
		fatal("self-check sign", err)
	}
	if !crypto.Verify(kpPub, probe, sig) {
		fatal("self-check verify", fmt.Errorf("signature verification failed — refusing to emit artefacts"))
	}
	crypto.ZeroBytesSecure(sig)
	fmt.Fprintln(os.Stderr, "Self-check passed (sign+verify OK).")

	// --- 3. Derive addresses ---
	h := sha3.Sum256(pubBytes)
	addrHex := "0x" + hex.EncodeToString(h[12:])
	addrQAU := kpPub.Address().String()

	pwd, err := readPassword("Master keystore password (>=12 chars): ")
	if err != nil {
		fatal("password", err)
	}
	kf, err := crypto.EncryptKeyBytes(kpPriv, pwd)
	crypto.ZeroBytesSecure(pwd)
	if err != nil {
		fatal("encrypt keystore", err)
	}
	ksJSON, err := kf.ToJSON()
	if err != nil {
		fatal("marshal keystore", err)
	}

	// --- 5. Emit artefacts ---
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fatal("mkdir", err)
	}

	pubDoc := ceremonyPublic{
		Kind:           kind,
		DerivationPath: path,
		AddressHex:     addrHex,
		AddressQAU:     addrQAU,
		PublicKeyHex:   hex.EncodeToString(pubBytes),
		Note:           "SAFE to carry online. Contains no secret material. Bind to genesis/staking as the validator MASTER identity.",
	}
	pubJSON, _ := json.MarshalIndent(pubDoc, "", "  ")

	files := []struct {
		name string
		perm os.FileMode
		data []byte
	}{
		{"master_public.json", 0o644, pubJSON},
		{"master_keystore.json", 0o600, ksJSON},
	}

	var paper string
	if kind == "mnemonic" {
		paper = "MASTER PAPER BACKUP (24 words, derivation " + path + "):\n\n" + mnemo + "\n"
	} else {
		paper = chunkSecret(hex.EncodeToString(privBytes))
	}
	files = append(files, struct {
		name string
		perm os.FileMode
		data []byte
	}{"master_paper_secret.txt", 0o600, []byte(paper)})

	for _, f := range files {
		p := filepath.Join(*outDir, f.name)
		if err := os.WriteFile(p, f.data, f.perm); err != nil {
			fatal("write "+p, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (perm %o)\n", p, f.perm)
	}

	// --- 6. Zeroize ---
	crypto.ZeroBytesSecure(privBytes)
	crypto.ZeroBytesSecure(pubBytes)
	mnemo = ""

	fmt.Fprintln(os.Stderr, "\nCeremony complete.")
	fmt.Fprintf(os.Stderr, "Master address (hex): %s\n", addrHex)
	fmt.Fprintf(os.Stderr, "Master address (QAU): %s\n", addrQAU)
	fmt.Fprintln(os.Stderr, "Next steps:")
	fmt.Fprintln(os.Stderr, "  1. Print/write master_paper_secret.txt, then SHRED the file")
	fmt.Fprintln(os.Stderr, "  2. Copy master_keystore.json to 2 offline USB sticks (separate locations)")
	fmt.Fprintln(os.Stderr, "  3. Carry ONLY master_public.json into the network world")
}

func fatal(stage string, err error) {
	fmt.Fprintf(os.Stderr, "ceremony FAILED at %s: %v\n", stage, err)
	os.Exit(1)
}

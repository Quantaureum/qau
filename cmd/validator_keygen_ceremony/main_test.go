// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// TestCeremonyEndToEnd runs the whole binary logic: generate (random mode),
// encrypt keystore, decrypt and confirm the round-trip, and validate the
// public artefact fields.
func TestCeremonyEndToEnd(t *testing.T) {
	out := t.TempDir()
	t.Setenv("QAU_KEYSTORE_PASSWORD", "test-ceremony-pwd-0001")

	// cheat: call main() with args
	oldArgs := os.Args
	os.Args = []string{"validator_keygen_ceremony", "-out", out}
	defer func() { os.Args = oldArgs }()
	main()

	// artefacts exist
	pubRaw, err := os.ReadFile(filepath.Join(out, "master_public.json"))
	if err != nil {
		t.Fatal(err)
	}
	ksRaw, err := os.ReadFile(filepath.Join(out, "master_keystore.json"))
	if err != nil {
		t.Fatal(err)
	}
	paperRaw, err := os.ReadFile(filepath.Join(out, "master_paper_secret.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// pub fields sane
	var pubDoc ceremonyPublic
	if err := json.Unmarshal(pubRaw, &pubDoc); err != nil {
		t.Fatal(err)
	}
	if pubDoc.Kind != "random" {
		t.Fatalf("kind: want random, got %s", pubDoc.Kind)
	}
	if !strings.HasPrefix(pubDoc.AddressHex, "0x") || len(pubDoc.AddressHex) != 42 {
		t.Fatalf("bad address hex: %q", pubDoc.AddressHex)
	}
	if len(pubDoc.PublicKeyHex) != crypto.Dilithium3PublicKeySize*2 {
		t.Fatalf("pubkey hex len %d", len(pubDoc.PublicKeyHex))
	}

	// perms (POSIX only — Windows ignores mode bits)
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(out, "master_keystore.json")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("keystore perm %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(out, "master_paper_secret.txt")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("paper perm %v", fi.Mode().Perm())
		}
	}

	// decrypt keystore and check pubkey matches
	kf, err := crypto.KeyFileFromJSON(ksRaw)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.DecryptKeyBytes(kf, []byte("test-ceremony-pwd-0001"))
	if err != nil {
		t.Fatal(err)
	}
	gotPub := hex.EncodeToString(priv.PublicKey().Bytes())
	if gotPub != pubDoc.PublicKeyHex {
		t.Fatal("keystore pubkey does not match public artefact")
	}

	// wrong password must fail
	if _, err := crypto.DecryptKeyBytes(kf, []byte("wrong-password-999")); err == nil {
		t.Fatal("decrypt with wrong password must fail")
	}

	// paper backup reassembly → same key
	chunks := regexp.MustCompile(`Chunk \d+: ([0-9a-f]+)  #CRC32:([0-9a-f]{8})`).FindAllStringSubmatch(string(paperRaw), -1)
	if len(chunks) == 0 {
		t.Fatal("no chunks parsed")
	}
	var sb strings.Builder
	for _, c := range chunks {
		sb.WriteString(c[1])
	}
	privHex := sb.String()
	if hex.EncodeToString(priv.Bytes()) != privHex {
		t.Fatal("paper-reassembled key does not match keystore key")
	}
}

// TestGenerateMnemonic validates wordlist checks and 24-word output.
func TestGenerateMnemonic(t *testing.T) {
	wl := make([]string, 2048)
	for i := range wl {
		wl[i] = "w" + strings.Repeat("a", 1) + strings.Repeat("b", 3) + padNum(i)
	}
	m, err := generateMnemonic(wl)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(m)); n != 24 {
		t.Fatalf("want 24 words, got %d", n)
	}
	if _, err := generateMnemonic(wl[:100]); err == nil {
		t.Fatal("short wordlist must error")
	}
}

func padNum(i int) string {
	s := []byte{'0', '0', '0', '0'}
	j := 3
	for i > 0 {
		s[j] = byte('0' + i%10)
		i /= 10
		j--
	}
	return string(s)
}

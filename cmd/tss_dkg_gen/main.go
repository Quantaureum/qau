// Quantaureum Node source, version 1.0.0.
// tss_dkg_gen — offline air-gapped DKG ceremony tool for QTD threshold
// signature key generation.
//
// This tool runs the QTD distributed DKG path (single-process simulation
// of distributed DKG; see wallet/tss/dkg.go header docs for the
// TSS-R7-01 caveat) and produces TWO kinds of output artifacts per DKG run:
//
//  1. share_<N>.enc — per-validator encrypted single-share file. Each file
//     contains ONLY validator N's key share (plus the group public key)
//     wrapped by AES-256-GCM with scrypt(N=2^18) key derivation. The AAD
//     is tssMagic (the wallet/tss internal constant — see
//     wallet/tss/dkg_ceremony.go:EncryptSingleShareBlob). This file is what
//     each validator's tssKeyShareFile in config.json points at; the node
//     decrypts it on startup via ImportKeySharesEncrypted and ends up with
//     exactly ONE share keyed by ParticipantID=N.
//
//  2. group_public_key.bin — raw group public key export (Rho || T1 ||
//     PubKey per ExportGroupPublicKey format). All validators share the
//     same group key and each one loads it via tssGroupKeyFile (or rely on
//     the embedded copy inside share_<N>.enc — encrypted single-share
//     import path also extracts the group key).
//
// CEREMONY CONTRACT:
//   - Air-gapped host. No network, no shared disks, no telemetry. After the
//     run completes, the host is wiped (power-cycle to clear DRAM). The
//     process calls ZeroizeAllShares() on exit, but only a power cycle
//     guarantees DRAM/SRAM clearance of the per-share S1/S2/T0 bytes after
//     Split.
//   - T>=2 (default): distributed DKG path (no env var needed on air-gapped
//     host). The process samples per-participant s1_i/s2_i from independent
//     crypto/rand and aggregates them in memory before split. Whoever
//     controls THIS process can Lagrange-interpolate the group private key
//     — the air-gap host is the single point of trust.
//   - T=1 (single-signer): NOT supported by this tool. Use cmd/genvalidator
//     with QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 instead.
//
// OUTPUT for a 4-of-6 threshold ceremony:
//
//	./dkg_output/
//	  share_1.enc
//	  share_2.enc
//	  share_3.enc
//	  share_4.enc
//	  share_5.enc
//	  share_6.enc
//	  group_public_key.bin
//
// Distribute each encrypted share only to its corresponding validator through
// a secure out-of-band channel, and distribute the group public key to every
// validator. The deployment chooses the destination filenames and directories.
//
// USAGE (on air-gapped host):
//
//	export QAU_TSS_PASSWORD="<32+_byte_random_secret>"  # MUST match qaud's QAU_VALIDATOR_KEY_PASSWORD
//	tss_dkg_gen -threshold 4 -total-shares 6 -output-dir /mnt/usb/dkg_output
//
// VALIDATION (R40.D commit pre-conditions):
//
//	go build ./...
//	go test ./cmd/tss_dkg_gen/...
//	go vet ./cmd/tss_dkg_gen/...
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// singleShareBlob builds the unencrypted wire payload for one validator's
// share file. The format mirrors ImportKeyShares()'s expected input,
// EXCEPT shareCount is 1 and only the Nth validator's share is present.
//
// Layout (matches wallet/tss/manager.go:exportKeyShares):
//
//	uint16 shareCount (= 1)
//	uint32 shareLen  ||  shareBytes
//	uint32 groupKeyLen  ||  groupKeyBytes
//
// The receiver (ImportKeySharesEncrypted -> ImportKeyShares) decrypts this
// blob and feeds it directly to ImportKeyShares, which populates
// m.qtdShares[N] = share. The node ends up holding ONLY its own share — the
// threshold-distributed invariant required by node/tss_distributed.go.
func singleShareBlob(share *qtd.QTDShare, groupKeyBlob []byte) ([]byte, error) {
	if share == nil {
		return nil, fmt.Errorf("nil share")
	}
	shareBytes := share.Encode()
	if shareBytes == nil {
		return nil, fmt.Errorf("share Encode() returned nil for participant %d", share.ParticipantID)
	}

	// Reuse the same layout ImportKeyShares parses. We deliberately mirror
	// wallet/tss/manager.go:exportKeyShares: uint16 count || (uint32 len ||
	// bytes)* || uint32 groupKeyLen || groupKeyBytes.
	totalLen := 2 + (4 + len(shareBytes)) + (4 + len(groupKeyBlob))
	buf := make([]byte, 0, totalLen)

	// shareCount = 1
	buf = binary.BigEndian.AppendUint16(buf, 1)
	// uint32 shareLen || shareBytes
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(shareBytes)))
	buf = append(buf, shareBytes...)
	// uint32 groupKeyLen || groupKeyBytes
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(groupKeyBlob)))
	buf = append(buf, groupKeyBlob...)
	return buf, nil
}

// validatePassword enforces a minimum password length. scrypt with N=2^18
// makes brute force expensive, but a too-short password still narrows the
// entropy pool. We mandate >=16 bytes (>=128 bits) for any TSS key-share
// encryption password.
func validatePassword(pwd []byte) error {
	const minPwdLen = 16
	if len(pwd) < minPwdLen {
		return fmt.Errorf("password too short: %d bytes (minimum %d). "+
			"Use a CSPRNG-generated secret of at least 32 bytes for production "+
			"(recommended: `python -c \"import secrets;print(secrets.token_urlsafe(48))\"`)",
			len(pwd), minPwdLen)
	}
	return nil
}

// getAllShares returns all []*qtd.QTDShare held by the manager. We need this
// because the public API only exposes GetShare (which strips to *KeyShare,
// losing S2/T0 bytes needed for distributed signing) and GetQTDShare(oneID).
// We iterate using GetQTDShare for 1..TotalShares to preserve the bytes.
func getAllShares(mgr *tss.TSSManager, totalShares int) ([]*qtd.QTDShare, error) {
	out := make([]*qtd.QTDShare, 0, totalShares)
	for id := 1; id <= totalShares; id++ {
		qs, err := mgr.GetQTDShare(id)
		if err != nil {
			return nil, fmt.Errorf("GetQTDShare(%d): %w", id, err)
		}
		out = append(out, qs)
	}
	return out, nil
}

// resolvePassword pulls the TSS password from (in order) the -password flag,
// the QAU_TSS_PASSWORD env var, or fails loudly. The password MUST match the
// validators' QAU_VALIDATOR_KEY_PASSWORD env var (or ValidatorPasswordFile
// content) so the node can decrypt the share file on startup.
func resolvePassword(pwdFlag string) ([]byte, error) {
	if pwdFlag != "" {
		return []byte(pwdFlag), nil
	}
	if env := os.Getenv("QAU_TSS_PASSWORD"); env != "" {
		return []byte(env), nil
	}
	return nil, fmt.Errorf("no TSS password provided: use -password or set QAU_TSS_PASSWORD env var " +
		"(MUST match qaud's QAU_VALIDATOR_KEY_PASSWORD on each validator)")
}

// persistEncryptedSingleShare writes one validator's single-share encrypted
// file to outputDir/share_<N>.enc with mode 0600.
func persistEncryptedSingleShare(outputDir string, participantID int, enc []byte) (string, error) {
	path := filepath.Join(outputDir, fmt.Sprintf("share_%d.enc", participantID))
	if err := os.WriteFile(path, enc, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// persistGroupPublicKey writes the raw group public key export to outputDir.
// This file is the same one node-side TSSGroupKeyFile expects.
func persistGroupPublicKey(outputDir, name string, data []byte) (string, error) {
	path := filepath.Join(outputDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// shortHex renders a short hex fingerprint (first 16 hex chars) for
// logging — useful for operators to eyeball whether two ceremony runs
// produced distinct group keys without leaking the full key in logs.
func shortHex(b []byte) string {
	const show = 8 // bytes = 16 hex chars
	if len(b) < show {
		return fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("%x…", b[:show])
}

func main() {
	threshold := flag.Int("threshold", 4, "TSS threshold T (must be >= 2; T=1 is single-signer mode and is NOT supported by this tool)")
	totalShares := flag.Int("total-shares", 6, "TSS total shares N (N >= T, max 100)")
	outputDir := flag.String("output-dir", "./dkg_output", "Output directory for share_<N>.enc files and group_public_key.bin")
	groupKeyFileName := flag.String("group-key-file", "group_public_key.bin", "Filename for the group public key export (saved in output-dir)")
	password := flag.String("password", "", "deprecated and rejected; use QAU_TSS_PASSWORD or the interactive prompt")
	seedHex := flag.String("seed-hex", "", "(optional) deterministic DKG seed in hex. Most ceremonies should leave this empty for crypto/rand-based DKG. Setting this requires QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1.")
	dryRun := flag.Bool("dry-run", false, "If set, performs DKG and prints fingerprints WITHOUT writing any files. Useful for ceremony rehearsal.")
	flag.Parse()
	if flagWasProvided("password") {
		fmt.Fprintln(os.Stderr, "[tss_dkg_gen] FATAL: -password is insecure because process listings expose argv; use QAU_TSS_PASSWORD")
		os.Exit(1)
	}

	if err := run(*threshold, *totalShares, *outputDir, *groupKeyFileName, *password, *seedHex, *dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "[tss_dkg_gen] FATAL: %v\n", err)
		os.Exit(1)
	}
}

func flagWasProvided(name string) bool {
	provided := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func run(threshold, totalShares int, outputDir, groupKeyFileName, passwordFlag, seedHex string, dryRun bool) error {
	started := time.Now()
	fmt.Println("========================================")
	fmt.Println("  Quantaureum QTD DKG Ceremony Tool")
	fmt.Println("========================================")
	fmt.Printf("Threshold (T)    : %d\n", threshold)
	fmt.Printf("Total Shares (N) : %d\n", totalShares)
	fmt.Printf("Output Dir       : %s\n", outputDir)
	fmt.Printf("Group Key File   : %s\n", groupKeyFileName)
	if dryRun {
		fmt.Println("Mode             : DRY RUN (no files written)")
	} else {
		fmt.Println("Mode             : PRODUCTION (files will be written with mode 0600)")
	}
	fmt.Println()

	// 1. Validate parameters
	if threshold < 2 {
		return fmt.Errorf("threshold=%d is not supported by this tool: T>=2 is required for "+
			"threshold security. (T=1 is single-signer mode. If you genuinely need T=1, use a "+
			"plain Dilithium3 keygen like cmd/genvalidator with QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1)",
			threshold)
	}
	if totalShares < threshold {
		return fmt.Errorf("totalShares=%d < threshold=%d: must have N >= T", totalShares, threshold)
	}
	if totalShares > 100 {
		return fmt.Errorf("totalShares=%d exceeds the TSS hard limit (100)", totalShares)
	}
	pwd, err := resolvePassword(passwordFlag)
	if err != nil {
		return err
	}
	if err := validatePassword(pwd); err != nil {
		return err
	}

	// 2. Build TSSConfig and create manager. Seed is propagated into config
	// ONLY if the user opted in (uncommon — most ceremonies want crypto/rand).
	cfg := tss.TSSConfig{
		Threshold:     threshold,
		TotalShares:   totalShares,
		SecurityLevel: 256,
	}
	if seedHex != "" {
		// Seeded mode is only available via the trusted-dealer path. We
		// refuse to silently use a seed with the distributed path (the
		// distributed path itself rejects seeds — this guard produces a
		// clearer error).
		if os.Getenv("QAU_ALLOW_TRUSTED_DEALER_CEREMONY") != "1" {
			return fmt.Errorf("-seed-hex was provided but QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 is not set. " +
				"Seeded DKG is the trusted-dealer path (full key reconstructed in memory) and requires the env var to acknowledge that risk.")
		}
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return fmt.Errorf("decode -seed-hex: %w", err)
		}
		if len(seed) < 32 {
			return fmt.Errorf("-seed-hex must be at least 32 bytes; got %d", len(seed))
		}
		cfg.Seed = seed
		fmt.Println("WARNING: deterministic seed mode is active. The owner of this seed " +
			"can reconstruct the full group private key. Use only in audited ceremonies.")
	}

	mgr, err := tss.NewTSSManager(cfg)
	if err != nil {
		return fmt.Errorf("NewTSSManager: %w", err)
	}
	defer mgr.ZeroizeAllShares()

	// 3. Run DKG. For T>=2 + default path we use GenerateKeyShares()
	// (distributed-simulated — TSS-R7-07 single-process simulation). For
	// T>=2 + seed (trusted-dealer seeded path) we use GenerateKeySharesTrustedDealer().
	fmt.Println("[1/4] Running DKG (this may take 5-15 seconds for 4-of-6 ...)")
	if len(cfg.Seed) > 0 {
		// Trusted-dealer seeded path. Already gated above by env var.
		if _, err := mgr.GenerateKeySharesTrustedDealer(); err != nil {
			return fmt.Errorf("GenerateKeySharesTrustedDealer: %w", err)
		}
	} else {
		// Default distributed-simulated DKG (TSS-R7-07).
		if _, err := mgr.GenerateKeyShares(); err != nil {
			return fmt.Errorf("GenerateKeyShares: %w", err)
		}
	}

	shares, err := getAllShares(mgr, totalShares)
	if err != nil {
		return fmt.Errorf("collect shares: %w", err)
	}
	if len(shares) != totalShares {
		return fmt.Errorf("internal error: expected %d shares, got %d", totalShares, len(shares))
	}
	fmt.Printf("      DKG complete: %d shares produced\n", len(shares))

	// 4. Export group public key (Rho || T1 || PubKey) ONCE — shared by all
	// validators via TSSGroupKeyFile.
	fmt.Println("[2/4] Exporting group public key ...")
	groupKeyBlob, err := mgr.ExportGroupPublicKey()
	if err != nil {
		return fmt.Errorf("ExportGroupPublicKey: %w", err)
	}
	fmt.Printf("      group_public_key.bin size=%d bytes (Rho+T1+PubKey)\n", len(groupKeyBlob))
	fmt.Printf("      PubKey fingerprint (first 16 hex): %s\n", shortHex(mgr.GroupPublicKey()))

	// 5. Build, encrypt, and write each single-share file. The encryption
	// helper (tss.EncryptSingleShareBlob) uses the SAME AAD (tssMagic) the
	// node's ImportKeySharesEncrypted path uses — so each share_<N>.enc
	// decrypts cleanly on the validator with the matching
	// QAU_VALIDATOR_KEY_PASSWORD.
	fmt.Println("[3/4] Encrypting and writing per-validator share files ...")

	if !dryRun {
		// Create output dir with 0700 (operator-only). MkdirAll honors the
		// explicit perm only when creating, so we fixup if pre-existing.
		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			return fmt.Errorf("MkdirAll(%s): %w", outputDir, err)
		}
		if info, err := os.Stat(outputDir); err == nil {
			if info.Mode().Perm() != 0o700 {
				// Best-effort chmod; ignore failures (operator may have
				// intentionally set group read on a screened ceremony host).
				_ = os.Chmod(outputDir, 0o700)
			}
		} else {
			return fmt.Errorf("stat %s: %w", outputDir, err)
		}
	}

	writtenFiles := make([]string, 0, totalShares+1)
	for _, share := range shares {
		// Build single-share plaintext wire blob (binary.BigEndian layout
		// expected by ImportKeyShares).
		plaintext, err := singleShareBlob(share, groupKeyBlob)
		if err != nil {
			return fmt.Errorf("build single-share blob for participant %d: %w", share.ParticipantID, err)
		}
		// Encrypt with AES-256-GCM + scrypt(N=2^18). tssMagic is used as
		// AAD internally (matching ImportKeySharesEncrypted on the node) —
		// so the encrypted file decrypts cleanly on the validator.
		enc, err := tss.EncryptSingleShareBlob(plaintext, pwd)
		if err != nil {
			tss.SecureZero(plaintext)
			return fmt.Errorf("encrypt single-share blob for participant %d: %w", share.ParticipantID, err)
		}
		// Wipe the plaintext immediately.
		tss.SecureZero(plaintext)

		if dryRun {
			fmt.Printf("      [DRY] would write share_%d.enc (%d bytes encrypted)\n",
				share.ParticipantID, len(enc))
			continue
		}
		path, err := persistEncryptedSingleShare(outputDir, share.ParticipantID, enc)
		if err != nil {
			return err
		}
		writtenFiles = append(writtenFiles, path)
		fmt.Printf("      wrote share_%d.enc  ->  %s  (%d bytes encrypted)\n",
			share.ParticipantID, path, len(enc))
	}

	// 6. Write group public key file
	if !dryRun {
		gpkPath, err := persistGroupPublicKey(outputDir, groupKeyFileName, groupKeyBlob)
		if err != nil {
			return err
		}
		writtenFiles = append(writtenFiles, gpkPath)
		fmt.Printf("      wrote %s -> %s (%d bytes)\n", groupKeyFileName, gpkPath, len(groupKeyBlob))
	} else {
		fmt.Printf("      [DRY] would write %s (%d bytes)\n", groupKeyFileName, len(groupKeyBlob))
	}

	// 7. Print summary + ceremony covenant
	fmt.Println()
	fmt.Println("[4/4] Ceremony summary")
	fmt.Println("-------------------------------")
	fmt.Printf("Threshold(T)            : %d\n", threshold)
	fmt.Printf("TotalShares(N)          : %d\n", totalShares)
	fmt.Printf("GroupPubKey fingerprint : %s\n", shortHex(mgr.GroupPublicKey()))
	fmt.Printf("Files written           : %d\n", len(writtenFiles))
	fmt.Printf("Elapsed                 : %s\n", time.Since(started))
	fmt.Println()
	fmt.Println("CEREMONY COVENANT")
	fmt.Println("-------------------------------")
	fmt.Println("1. Verify each share_<N>.enc fingerprint against the on-host fingerprint log.")
	fmt.Println("2. Distribute share_<N>.enc to validator N via OUT-OF-BAND CHANNEL (USB, QR, secure courier).")
	fmt.Println("3. Distribute group_public_key.bin to ALL validators (same file).")
	fmt.Println("4. On each validator, set in config.json:")
	fmt.Println(`       "tssKeyShareFile":    "/var/lib/quantaureum/tss/share_<N>.enc"`)
	fmt.Println(`       "tssGroupKeyFile":    "/var/lib/quantaureum/tss/group_public_key.bin"`)
	fmt.Printf("       \"tssThreshold\":      %d\n", threshold)
	fmt.Printf("       \"tssTotalShares\":    %d\n", totalShares)
	fmt.Println(`       "tssDistributedMode": true`)
	fmt.Println("5. Ensure QAU_VALIDATOR_KEY_PASSWORD matches -password on EACH validator node.")
	fmt.Println("6. After distribution, ZEROISE this host: power-cycle the air-gapped machine")
	fmt.Println("   (ZeroizeAllShares() cleared in-process memory, but DRAM retains remanence).")
	fmt.Println("7. Test on devnet BEFORE mainnet — see localtest/diagnostics/README-QTD-DEPLOY.md.")
	fmt.Println("========================================")
	return nil
}

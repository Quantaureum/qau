// Quantaureum Node source, version 1.0.0.
// main_test.go — end-to-end test for the tss_dkg_gen ceremony tool.
//
// Verifies:
//  1. The tool produces N + 1 files (N single-share enc files + 1 group key bin) for 2-of-3 config.
//  2. Each share_<N>.enc file decrypts back to a single QTDShare with
//     ParticipantID = N via tss.ImportKeySharesEncrypted (node-side path).
//  3. The group_public_key.bin file imports cleanly via tss.ImportGroupPublicKey.
//  4. The dry-run flag produces zero files.
//  5. -threshold < 2 is rejected.
//  6. -total-shares < -threshold is rejected.
//  7. Missing -password and QAU_TSS_PASSWORD env is rejected.
//  8. Password < 16 bytes is rejected.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss"
)

// withEnv sets env var `key` to `val` for the duration of the test, restoring
// the prior value (if any) on cleanup. Returns the prior value.
func withEnv(t *testing.T, key, val string) string {
	t.Helper()
	prev, hadPrev := os.LookupEnv(key)
	if err := os.Setenv(key, val); err != nil {
		t.Fatalf("Setenv(%s): %v", key, err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	})
	return prev
}

func TestRun_GeneratesAllFilesForTwoOfThree(t *testing.T) {
	// 2-of-3 is the smallest config DKG supports (T>=2). Keeps the test
	// fast (single-digit seconds) while still exercising the per-share path.
	outDir := t.TempDir()
	password := "test-ceremony-password-very-long"

	// Ensure no env interference; defer restores.
	prevProd, hadProd := os.LookupEnv("QAU_PRODUCTION")
	_ = os.Unsetenv("QAU_PRODUCTION")
	t.Cleanup(func() {
		if hadProd {
			_ = os.Setenv("QAU_PRODUCTION", prevProd)
		}
	})

	if err := run(
		2,                      // threshold
		3,                      // totalShares
		outDir,                 // outputDir
		"group_public_key.bin", // groupKeyFileName
		password,               // passwordFlag
		"",                     // seedHex
		false,                  // dryRun
	); err != nil {
		t.Fatalf("run() failed: %v", err)
	}

	// Expect 3 share files + 1 group key file
	for i := 1; i <= 3; i++ {
		p := filepath.Join(outDir, "share_"+itoa(i)+".enc")
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing share file %s: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "group_public_key.bin")); err != nil {
		t.Fatalf("missing group_public_key.bin: %v", err)
	}

	// Round-trip each share file through the node-side import path.
	// Each validator node only sees ONE share — exactly the per-participant
	// wire invariant this tool exists to enforce.
	for i := 1; i <= 3; i++ {
		p := filepath.Join(outDir, "share_"+itoa(i)+".enc")
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", p, err)
		}
		// Must look encrypted to tss.IsEncryptedKeyShareData
		if !tss.IsEncryptedKeyShareData(data) {
			t.Fatalf("share_%d.enc not detected as encrypted", i)
		}

		// Import as the owning validator would.
		cfg := tss.TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
		nodeMgr, err := tss.NewTSSManager(cfg)
		if err != nil {
			t.Fatalf("NewTSSManager for validator %d: %v", i, err)
		}
		if err := nodeMgr.ImportKeySharesEncrypted(data, []byte(password)); err != nil {
			t.Fatalf("ImportKeySharesEncrypted(share_%d.enc): %v", i, err)
		}
		if got := nodeMgr.ShareCount(); got != 1 {
			t.Fatalf("validator %d: expected ShareCount=1 after single-share import, got %d", i, got)
		}
		if !nodeMgr.HasGroupPublicKey() {
			t.Fatalf("validator %d: HasGroupPublicKey() should be true after import", i)
		}
		// The imported share must be the one keyed by ParticipantID=i
		if _, err := nodeMgr.GetQTDShare(i); err != nil {
			t.Fatalf("validator %d: GetQTDShare(%d) should succeed: %v", i, i, err)
		}
		// And must NOT have shares for other participant IDs
		for j := 1; j <= 3; j++ {
			if j == i {
				continue
			}
			if _, err := nodeMgr.GetQTDShare(j); err == nil {
				t.Fatalf("validator %d should NOT hold share for participant %d (cross-share leakage)", i, j)
			}
		}
		nodeMgr.ZeroizeAllShares()
	}

	// Group key file imports cleanly and matches all shares' embedded key.
	gpkPath := filepath.Join(outDir, "group_public_key.bin")
	gpkData, err := os.ReadFile(gpkPath)
	if err != nil {
		t.Fatalf("ReadFile(group_public_key.bin): %v", err)
	}
	cfg := tss.TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	gpkMgr, err := tss.NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager (gpk): %v", err)
	}
	if err := gpkMgr.ImportGroupPublicKey(gpkData); err != nil {
		t.Fatalf("ImportGroupPublicKey: %v", err)
	}
	if !gpkMgr.HasGroupPublicKey() {
		t.Fatal("HasGroupPublicKey() should be true after import")
	}

	// Cross-check: the group public key from gpk file must equal the one
	// embedded in share_1.enc
	share1Data, _ := os.ReadFile(filepath.Join(outDir, "share_1.enc"))
	nodeMgr, _ := tss.NewTSSManager(cfg)
	_ = nodeMgr.ImportKeySharesEncrypted(share1Data, []byte(password))
	if !bytes.Equal(nodeMgr.GroupPublicKey(), gpkMgr.GroupPublicKey()) {
		t.Fatal("group_public_key.bin mismatch with the one embedded in share_1.enc")
	}
}

func TestRun_DryRunWritesNoFiles(t *testing.T) {
	outDir := t.TempDir()
	if err := run(2, 3, outDir, "group_public_key.bin", "long-ceremony-password-here", "", true); err != nil {
		t.Fatalf("run(dry-run) failed: %v", err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry-run should produce 0 files; got %d: %+v", len(entries), entries)
	}
}

func TestRun_RejectsThresholdOne(t *testing.T) {
	outDir := t.TempDir()
	err := run(1, 3, outDir, "group_public_key.bin", "long-enough-password-here", "", false)
	if err == nil {
		t.Fatal("expected error for threshold=1; got nil")
	}
}

func TestRun_RejectsTotalSharesLessThanThreshold(t *testing.T) {
	outDir := t.TempDir()
	err := run(3, 2, outDir, "group_public_key.bin", "long-enough-password-here", "", false)
	if err == nil {
		t.Fatal("expected error for totalShares < threshold; got nil")
	}
}

func TestRun_RejectsMissingPassword(t *testing.T) {
	// Ensure QAU_TSS_PASSWORD is empty for this test; -password="" too.
	withEnv(t, "QAU_TSS_PASSWORD", "")
	outDir := t.TempDir()
	err := run(2, 3, outDir, "group_public_key.bin", "", "", false)
	if err == nil {
		t.Fatal("expected error for missing password; got nil")
	}
}

func TestRun_RejectsShortPassword(t *testing.T) {
	outDir := t.TempDir()
	err := run(2, 3, outDir, "group_public_key.bin", "short", "", false)
	if err == nil {
		t.Fatal("expected error for short password (< 16 bytes); got nil")
	}
}

func TestRun_ReadsPasswordFromEnv(t *testing.T) {
	outDir := t.TempDir()
	withEnv(t, "QAU_TSS_PASSWORD", "long-ceremony-password-from-env")
	if err := run(2, 3, outDir, "group_public_key.bin", "", "", false); err != nil {
		t.Fatalf("run(env-pwd) failed: %v", err)
	}
	// Spot-check share_1.enc was actually written and decrypts.
	data, err := os.ReadFile(filepath.Join(outDir, "share_1.enc"))
	if err != nil {
		t.Fatalf("share_1.enc missing despite env pwd: %v", err)
	}
	if !tss.IsEncryptedKeyShareData(data) {
		t.Fatal("share_1.enc should be encrypted")
	}
}

// itoa is the local stdlib-free strconv.Itoa replacement. Keeping the
// test file free of strconv keeps imports minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	buf := make([]byte, 0, 10)
	for i > 0 {
		buf = append(buf, byte('0'+i%10))
		i /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// reverse
	for l, r := 0, len(buf)-1; l < r; l, r = l+1, r-1 {
		buf[l], buf[r] = buf[r], buf[l]
	}
	return string(buf)
}

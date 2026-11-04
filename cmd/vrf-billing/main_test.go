// Quantaureum Node source, version 1.0.0.
package main

// Unit tests for the billing worker's pure logic: deposit decoding, day
// conversion, and state roundtrip. Network paths (runPass) are exercised
// end-to-end on the local devnet.

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// pad32 returns a 32-byte big-endian padding of v.
func pad32(t *testing.T, v string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 32 {
		t.Fatalf("value too long: %d bytes", len(raw))
	}
	out := make([]byte, 32)
	copy(out[32-len(raw):], raw)
	return out
}

func TestDecodeDeposit(t *testing.T) {
	payer := pad32(t, "1111111111111111111111111111111111111111")
	amount := pad32(t, "0de0b6b3a7640000") // 1e18
	keyHash := pad32(t, "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb")
	data := "0x" + hex.EncodeToString(append(append(payer, amount...), keyHash...))

	ev, err := decodeDeposit(ethLog{Data: data, TransactionHash: "0xdead"})
	if err != nil {
		t.Fatalf("decodeDeposit: %v", err)
	}
	if ev.Payer != "0x1111111111111111111111111111111111111111" {
		t.Errorf("Payer = %s", ev.Payer)
	}
	if ev.Amount.Cmp(big.NewInt(1e18)) != 0 {
		t.Errorf("Amount = %s", ev.Amount)
	}
	wantKeyHash := "0x" + hex.EncodeToString(keyHash)
	if ev.KeyHash != wantKeyHash {
		t.Errorf("KeyHash = %s, want %s", ev.KeyHash, wantKeyHash)
	}
	if ev.TxHash != "0xdead" {
		t.Errorf("TxHash = %s", ev.TxHash)
	}
}

func TestDecodeDepositRejectsBadData(t *testing.T) {
	if _, err := decodeDeposit(ethLog{Data: "0x1234"}); err == nil {
		t.Error("short data must be rejected")
	}
	if _, err := decodeDeposit(ethLog{Data: "0xzz"}); err == nil {
		t.Error("non-hex data must be rejected")
	}
}

func TestDayConversionFloors(t *testing.T) {
	weiPerDay := big.NewInt(1_000_000_000_000_000_000) // 1e18
	// 2.7 days of wei → 2 whole days.
	amount := new(big.Int).Mul(big.NewInt(27), big.NewInt(1e17))
	days := new(big.Int).Div(amount, weiPerDay).Int64()
	if days != 2 {
		t.Errorf("days = %d, want 2 (floor)", days)
	}
	// Below one day → 0 → the caller must skip.
	if got := new(big.Int).Div(big.NewInt(5e17), weiPerDay).Int64(); got != 0 {
		t.Errorf("days = %d, want 0 below one day", got)
	}
}

// TestSplitDays anchors the QR-24a days split: admin_extendAPIKey rejects a
// single call above 3650 days (rpc/admin_key_api.go apiKeyMaxDays), so a
// deposit worth more than ten years must be split into bounded batches.
func TestSplitDays(t *testing.T) {
	cases := []struct {
		total int64
		want  []int64
	}{
		{0, nil},
		{-5, nil},
		{1, []int64{1}},
		{3649, []int64{3649}},
		{3650, []int64{3650}},          // exactly one full batch
		{3651, []int64{3650, 1}},       // one day over → two calls
		{4000, []int64{3650, 350}},     // >3650 splits into two
		{7300, []int64{3650, 3650}},    // exactly two full batches
		{7301, []int64{3650, 3650, 1}}, // two full batches + remainder
		{10950, []int64{3650, 3650, 3650}},
	}
	for _, tc := range cases {
		got := splitDays(tc.total)
		if len(got) != len(tc.want) {
			t.Errorf("splitDays(%d) = %v, want %v", tc.total, got, tc.want)
			continue
		}
		var sum int64
		for i, b := range got {
			sum += b
			if b <= 0 || b > maxExtendDays {
				t.Errorf("splitDays(%d)[%d] = %d, out of (0,%d]", tc.total, i, b, maxExtendDays)
			}
			if i < len(tc.want) && b != tc.want[i] {
				t.Errorf("splitDays(%d)[%d] = %d, want %d", tc.total, i, b, tc.want[i])
			}
		}
		if tc.total > 0 && sum != tc.total {
			t.Errorf("splitDays(%d) batches sum to %d, want the total unchanged", tc.total, sum)
		}
	}
}

func TestStateRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := saveState(path, &billingState{LastProcessedBlock: 42}); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	s, err := loadState(path)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if s.LastProcessedBlock != 42 {
		t.Errorf("LastProcessedBlock = %d, want 42", s.LastProcessedBlock)
	}
	// Missing file = zero state, not an error.
	// Build the missing path under a nonexistent directory, not under the
	// state file itself: through a file component Linux yields ENOTDIR
	// (not matched by os.IsNotExist) while Windows yields ENOENT.
	s2, err := loadState(filepath.Join(t.TempDir(), "does-not-exist", "x.json"))
	if err != nil {
		t.Errorf("missing state file must not error, got %v", err)
	}
	if s2.LastProcessedBlock != 0 {
		t.Errorf("missing state file must yield zero state, got %d", s2.LastProcessedBlock)
	}
}

func TestStateDirCreatesParents(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b", "state.json")
	if err := stateDir(nested); err != nil {
		t.Fatalf("stateDir: %v", err)
	}
	if err := saveState(nested, &billingState{LastProcessedBlock: 7}); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatal(err)
	}
}

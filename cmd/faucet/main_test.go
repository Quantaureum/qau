// Quantaureum Node source, version 1.0.0.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// AUDIT run-3 qau.faucet/address-limit-case-variant-bypass regression test.
//
// The per-address faucet rate limit must key on a canonical address form. The
// handler previously used the raw request string ("addr:"+req.Address), so the
// same address written in different hex case produced different buckets and
// bypassed the limit.
func TestAddrRateKey_CaseVariantIsSameBucket(t *testing.T) {
	mixed := "0xAbCdEf0000000000000000000000000000000001"
	lower := "0xabcdef0000000000000000000000000000000001"

	a, err := types.ParseHexAddress(mixed)
	if err != nil {
		t.Fatalf("parse mixed case: %v", err)
	}
	b, err := types.ParseHexAddress(lower)
	if err != nil {
		t.Fatalf("parse lower case: %v", err)
	}
	if a != b {
		t.Fatal("case variants must parse to the same address")
	}
	if addrRateKey(a) != addrRateKey(b) {
		t.Fatalf("rate-limit keys differ for the same address: %q vs %q", addrRateKey(a), addrRateKey(b))
	}
}

func TestAddrRateKey_DistinctAddressesDiffer(t *testing.T) {
	a, _ := types.ParseHexAddress("0x0000000000000000000000000000000000000001")
	b, _ := types.ParseHexAddress("0x0000000000000000000000000000000000000002")
	if addrRateKey(a) == addrRateKey(b) {
		t.Fatal("distinct addresses must not share a rate-limit bucket")
	}
}

func TestAddrRateKey_UsesHexForm(t *testing.T) {
	a, _ := types.ParseHexAddress("0xAbCdEf0000000000000000000000000000000001")
	if got, want := addrRateKey(a), "addr:0xabcdef0000000000000000000000000000000001"; got != want {
		t.Fatalf("unexpected canonical key: got %q want %q", got, want)
	}
}

// AUDIT run-3 qau.faucet/daily-cap-not-persisted regression tests.
//
// dailyDispensed / dailyResetDate are the global cap that bounds total QAU
// dispensation regardless of Sybil identities. Restarting the faucet must not
// reset that cap.

func utcToday() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func newPersistedFaucet(path string, dispensed int, day time.Time) *FaucetService {
	return &FaucetService{
		rateLimitMap:   make(map[string]time.Time),
		persistPath:    path,
		dailyDispensed: dispensed,
		dailyResetDate: day,
	}
}

func TestDailyCapPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratelimit.json")
	fs1 := newPersistedFaucet(path, maxDailyDispense, utcToday())
	fs1.saveRateLimits()

	fs2 := newPersistedFaucet(path, 0, utcToday())
	fs2.loadRateLimits()

	if fs2.dailyDispensed != maxDailyDispense {
		t.Fatalf("daily cap not restored after restart: got %d want %d", fs2.dailyDispensed, maxDailyDispense)
	}
	if !fs2.dailyResetDate.Equal(utcToday()) {
		t.Fatalf("daily reset date not restored: got %v want %v", fs2.dailyResetDate, utcToday())
	}
}

func TestDailyCapYesterdayDoesNotCountToday(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratelimit.json")
	fs1 := newPersistedFaucet(path, maxDailyDispense, utcToday().Add(-24*time.Hour))
	fs1.saveRateLimits()

	fs2 := newPersistedFaucet(path, 0, time.Time{})
	fs2.loadRateLimits()

	if fs2.dailyDispensed != 0 {
		t.Fatalf("stale (yesterday) dispensation must not count toward today: got %d", fs2.dailyDispensed)
	}
	if !fs2.dailyResetDate.Equal(utcToday()) {
		t.Fatalf("reset date must advance to today: got %v want %v", fs2.dailyResetDate, utcToday())
	}
}

// TestDailyCapRestoredWhenRateLimitFileCorrupt pins the decoupling fix: the
// daily quota file must be loaded even when the per-identity rate-limit file
// is unreadable. Before the fix loadDailyState ran only after a successful
// rate-limit parse, so a corrupt rate-limit file reset the day's total.
func TestDailyCapRestoredWhenRateLimitFileCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratelimit.json")
	fs1 := newPersistedFaucet(path, maxDailyDispense, utcToday())
	fs1.saveRateLimits()

	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt rate limit file: %v", err)
	}

	fs2 := newPersistedFaucet(path, 0, utcToday())
	fs2.loadRateLimits()

	if fs2.dailyDispensed != maxDailyDispense {
		t.Fatalf("daily cap must survive a corrupt rate-limit file: got %d want %d",
			fs2.dailyDispensed, maxDailyDispense)
	}
}

// TestDailyCapCorruptDailyStateIsFailClosed pins the conservative value: a
// corrupt (or otherwise unreadable) daily quota file must be treated as a
// FULLY CONSUMED day, never as "nothing dispensed yet".
func TestDailyCapCorruptDailyStateIsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ratelimit.json")
	fs1 := newPersistedFaucet(path, 10, utcToday())
	fs1.saveRateLimits()

	if err := os.WriteFile(path+".daily", []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt daily state file: %v", err)
	}

	fs2 := newPersistedFaucet(path, 0, utcToday())
	fs2.loadRateLimits()

	if fs2.dailyDispensed != maxDailyDispense {
		t.Fatalf("a corrupt daily state must be treated as exhausted: got %d want %d",
			fs2.dailyDispensed, maxDailyDispense)
	}
	if !fs2.dailyResetDate.Equal(utcToday()) {
		t.Fatalf("fail-closed state must be dated today: got %v want %v", fs2.dailyResetDate, utcToday())
	}
}

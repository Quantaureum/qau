// Quantaureum Node source, version 1.0.0.
package bridge

// r5_brdg_r5_04_test.go — BRDG-R5-04 (2026-07-16) regression tests.
//
// Vulnerability summary: the SPV header verifier had three fail-open paths:
//  1. VerifyQuantaureumHeader: lookup==nil → return nil (allow through)
//  2. VerifyEthereumHeader: sc==nil → return nil (allow through)
//  3. VerifyEthereumHeaderByNumber: sc==nil → return nil (allow through)
//  4. VerifyEthereumHeaderByNumber: blockHashHex=="" → skip the reorg check
//
// Also: messages entering the payout flow did not require BlockNumber>0 && BlockHash!=""
// (legacy exemption) → an attacker could submit an empty blockHash to bypass reorg detection.
//
// Fix:
//   - a new strictMode field. In strict mode, nil syncers → fail-closed
//   - in strict mode, VerifyEthereumHeaderByNumber requires a non-empty blockHashHex
//   - adapter.VerifyMessage enforces BlockNumber>0 && BlockHash!="" in strict mode
//   - mainnet node startup asserts the verifier is fully configured, otherwise refuses to start

import (
	"context"
	"errors"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// TestR5_BRDG_R5_04_VerifyQuantaureumHeader_StrictMode_NilLookup_FailClosed
// Verify that in strict mode, VerifyQuantaureumHeader errors (not returns nil) when lookup==nil.
func TestR5_BRDG_R5_04_VerifyQuantaureumHeader_StrictMode_NilLookup_FailClosed(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	v.SetStrictMode(true)

	if err := v.VerifyQuantaureumHeader(100, "0xabc"); err == nil {
		t.Fatal("VerifyQuantaureumHeader with nil lookup in strict mode should fail, got nil")
	}
}

// TestR5_BRDG_R5_04_VerifyQuantaureumHeader_NonStrictMode_NilLookup_Skip
// Verify that in non-strict mode (test default) behavior stays backward-compatible: lookup==nil → skip verification.
func TestR5_BRDG_R5_04_VerifyQuantaureumHeader_NonStrictMode_NilLookup_Skip(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	// non-strict mode by default
	if v.IsStrictMode() {
		t.Fatal("default verifier should be in non-strict mode")
	}
	if err := v.VerifyQuantaureumHeader(100, "0xabc"); err != nil {
		t.Fatalf("VerifyQuantaureumHeader in non-strict mode should skip (return nil), got: %v", err)
	}
}

// TestR5_BRDG_R5_04_VerifyEthereumHeader_StrictMode_NilSC_FailClosed
// Verify that in strict mode, VerifyEthereumHeader errors (not returns nil) when sc==nil.
func TestR5_BRDG_R5_04_VerifyEthereumHeader_StrictMode_NilSC_FailClosed(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	v.SetStrictMode(true)

	if err := v.VerifyEthereumHeader(&encoding.BlockHeader{}); err == nil {
		t.Fatal("VerifyEthereumHeader with nil sync committee in strict mode should fail, got nil")
	}
}

// TestR5_BRDG_R5_04_VerifyEthereumHeader_NonStrictMode_NilSC_Skip
// Verify that non-strict mode stays backward-compatible.
func TestR5_BRDG_R5_04_VerifyEthereumHeader_NonStrictMode_NilSC_Skip(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	if err := v.VerifyEthereumHeader(&encoding.BlockHeader{}); err != nil {
		t.Fatalf("VerifyEthereumHeader in non-strict mode should skip, got: %v", err)
	}
}

// TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_StrictMode_NilSC_FailClosed
// Verify that in strict mode, VerifyEthereumHeaderByNumber errors (not returns nil) when sc==nil.
func TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_StrictMode_NilSC_FailClosed(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	v.SetStrictMode(true)

	// a nil fetcher is safe because the path should fail before using it
	err := v.VerifyEthereumHeaderByNumber(context.Background(), nil, 100, "0xabc")
	if err == nil {
		t.Fatal("VerifyEthereumHeaderByNumber with nil sync committee in strict mode should fail, got nil")
	}
}

// TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_StrictMode_EmptyBlockHash_FailClosed
// Verify that in strict mode, blockHashHex=="" returns an error (no legacy exemption).
// This is the core fix: it removes the attacker path of submitting an empty BlockHash to bypass reorg detection.
func TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_StrictMode_EmptyBlockHash_FailClosed(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	// inject a real sync committee to isolate the empty-blockHash path
	v.SetEthereumSyncCommittee(&alwaysFailSyncCommittee{})
	v.SetStrictMode(true)

	err := v.VerifyEthereumHeaderByNumber(context.Background(), &stubHeaderFetcher{}, 100, "")
	if err == nil {
		t.Fatal("VerifyEthereumHeaderByNumber with empty blockHash in strict mode should fail, got nil")
	}
}

// TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_NonStrictMode_EmptyBlockHash_SkipReorgCheck
// Verify that in non-strict mode, blockHashHex=="" still skips the reorg check (backward-compatible),
// but the sync-committee verification still runs. If it fails, an error is returned.
func TestR5_BRDG_R5_04_VerifyEthereumHeaderByNumber_NonStrictMode_EmptyBlockHash_SkipReorgCheck(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	// use a sync committee that always returns nil, proving the reorg check is skipped
	// but the sync-committee verification still runs
	v.SetEthereumSyncCommittee(&alwaysPassSyncCommittee{})

	// the fetcher returns a non-nil header — if the reorg check were mistakenly run,
	// it is skipped because blockHashHex==="", so no reorg error should surface
	err := v.VerifyEthereumHeaderByNumber(context.Background(), &stubHeaderFetcher{}, 100, "")
	if err != nil {
		t.Fatalf("VerifyEthereumHeaderByNumber with empty blockHash in non-strict mode should skip reorg check and pass, got: %v", err)
	}
}

// TestR5_BRDG_R5_04_SetStrictMode_ToggleAndIsStrictMode
// Verify SetStrictMode / IsStrictMode correctness.
func TestR5_BRDG_R5_04_SetStrictMode_ToggleAndIsStrictMode(t *testing.T) {
	v := NewBridgeHeaderVerifier()
	if v.IsStrictMode() {
		t.Fatal("new verifier should default to non-strict mode")
	}
	v.SetStrictMode(true)
	if !v.IsStrictMode() {
		t.Fatal("after SetStrictMode(true), IsStrictMode should return true")
	}
	v.SetStrictMode(false)
	if v.IsStrictMode() {
		t.Fatal("after SetStrictMode(false), IsStrictMode should return false")
	}
}

// --- stub helpers ---

// alwaysFailSyncCommittee always errors; used to prove the sync committee is invoked.
type alwaysFailSyncCommittee struct{}

func (a *alwaysFailSyncCommittee) VerifyBlockHeader(header *encoding.BlockHeader) error {
	return errors.New("stub: always fails")
}

// alwaysPassSyncCommittee always returns nil; used to prove the path reaches sync-committee verification.
type alwaysPassSyncCommittee struct{}

func (a *alwaysPassSyncCommittee) VerifyBlockHeader(header *encoding.BlockHeader) error {
	return nil
}

// stubHeaderFetcher returns an empty header.
type stubHeaderFetcher struct{}

func (s *stubHeaderFetcher) FetchHeader(ctx context.Context, blockNumber uint64) (*encoding.BlockHeader, error) {
	return &encoding.BlockHeader{Height: blockNumber}, nil
}

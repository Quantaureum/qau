// Quantaureum Node source, version 1.0.0.
// Package bridge header_verifier.go provides SPV header verification for
// cross-chain messages.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification (BRDG-04/HIGH-12/
// HIGH-15). Stage 1 (SetCommittedRoot + FetchMerkleRootFromChain) eliminated
// single-point trust on the Merkle root by reading it from the on-chain bridge
// contract. Stage 2 adds header chain verification to detect source-chain
// reorganizations: a message carrying a fabricated BlockHash, or a message
// whose source block was reorged away, is rejected before execution.
//
// Design:
//   - Quantaureum side: uses a HeaderLookup (satisfied by
//     lightclient.HeaderSyncer) to look up the block header at msg.BlockNumber
//     in the local block store and compare its hash to msg.BlockHash.
//     A mismatch indicates a reorg.
//   - External-chain side: uses a SyncCommitteeChecker (satisfied by
//     lightclient.SyncCommitteeVerifier) to verify Dilithium3 sync committee
//     signatures over QAU-format headers (encoding.BlockHeader). This is the
//     format used by QAU-homogeneous external chains; it is NOT Ethereum's
//     BLS12-381 SyncAggregate (which lives in beacon blocks, not execution
//     headers). Ethereum consensus requires a dedicated BLS verifier.
//
// To avoid an import cycle (bridge → lightclient → rpc → bridge), this file
// defines interfaces that the lightclient types satisfy. The bridge package
// never imports lightclient directly — callers inject the concrete types via
// the setter methods.
//
// The verifier is nil-safe: when not configured (nil), header verification is
// skipped. In production, node startup MUST inject both syncers. Note that an
// injected sync committee verifier with no committee loaded cannot verify
// signatures; callers must check IsExternalChainSyncCommitteeReady and treat
// ready=false as reorg-detection-only (R3-02).
package bridge

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
)

// HeaderLookup looks up block headers by height. Satisfied by
// lightclient.HeaderSyncer — defined as an interface here to avoid an import
// cycle (bridge → lightclient → rpc → bridge).
type HeaderLookup interface {
	// GetHeaderByHeight retrieves the block header at the given height.
	GetHeaderByHeight(height uint64) (*encoding.BlockHeader, error)
}

// SyncCommitteeChecker verifies block headers using sync committee signatures.
// Satisfied by lightclient.SyncCommitteeVerifier — defined as an interface
// here to avoid an import cycle.
type SyncCommitteeChecker interface {
	// VerifyBlockHeader verifies a block header using sync committee signatures.
	VerifyBlockHeader(header *encoding.BlockHeader) error
}

// SyncCommitteeReadiness is optionally implemented by a SyncCommitteeChecker
// that can report whether a non-empty committee is actually loaded. A checker
// without a committee cannot verify signatures, so strict-mode startup checks
// must use this interface instead of a non-nil pointer check (R3-02).
type SyncCommitteeReadiness interface {
	HasActiveCommittee() bool
}

// HeaderFetcher fetches block headers from a blockchain by block number.
// Implemented by chain adapters that have RPC access to the target chain.
// Used by BridgeHeaderVerifier to fetch headers for sync committee verification.
type HeaderFetcher interface {
	// FetchHeader retrieves the block header at the given block number.
	// Returns an error if the block is not found or the RPC fails.
	FetchHeader(ctx context.Context, blockNumber uint64) (*encoding.BlockHeader, error)
}

// BridgeHeaderVerifier provides SPV header verification for cross-chain messages.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification.
//
// Security model:
//   - When configured, VerifyMessage calls header verification BEFORE accepting
//     a message. A reorg (block hash mismatch) or invalid sync committee
//     signature causes the message to be rejected.
//   - When NOT configured (nil) and strictMode is false (test default), header
//     verification is skipped. Production deployments MUST inject both syncers
//     during node startup via SetQuantaureumHeaderLookup and
//     SetExternalChainSyncCommittee, AND enable strictMode via SetStrictMode(true).
//   - AUDIT (2026 security review) BRDG-FIX: When strictMode is true (production),
//     nil syncers cause Verify* methods to return an error (fail-closed),
//     eliminating the fail-open path where an unconfigured verifier silently
//     accepts messages. Additionally, VerifyExternalChainHeaderByNumber requires
//     a non-empty blockHashHex (no legacy exemption for messages without a
//     block hash).
type BridgeHeaderVerifier struct {
	mu                         sync.RWMutex
	quantaureumLookup          HeaderLookup
	externalChainSyncCommittee SyncCommitteeChecker
	// strictMode enforces fail-closed behavior when syncers are nil.
	// Default false (test backward compatibility). Set to true in production
	// via SetStrictMode(true) during node startup.
	// BRDG-FIX (2026-07-16).
	strictMode bool
}

// NewBridgeHeaderVerifier creates a new header verifier with no syncers
// configured. Use SetQuantaureumHeaderLookup and SetExternalChainSyncCommittee to
// inject the syncers during node startup.
func NewBridgeHeaderVerifier() *BridgeHeaderVerifier {
	return &BridgeHeaderVerifier{}
}

// SetQuantaureumHeaderLookup injects the Quantaureum header lookup (typically
// a *lightclient.HeaderSyncer). When set, VerifyQuantaureumHeader verifies
// that the block at a given height has the expected hash (reorg detection) by
// looking it up in the local block store.
func (v *BridgeHeaderVerifier) SetQuantaureumHeaderLookup(l HeaderLookup) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.quantaureumLookup = l
}

// SetExternalChainSyncCommittee injects the external-chain sync committee
// verifier (typically a *lightclient.SyncCommitteeVerifier). The verifier
// checks Dilithium3 signatures over QAU-format headers; it does not implement
// Ethereum's BLS12-381 committee. When set, VerifyExternalChainHeader verifies
// sync committee signatures on headers fetched from the external chain.
func (v *BridgeHeaderVerifier) SetExternalChainSyncCommittee(sc SyncCommitteeChecker) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.externalChainSyncCommittee = sc
}

// IsEnabled returns true if any header verification is configured.
// When false, all Verify* methods are no-ops (skip verification).
func (v *BridgeHeaderVerifier) IsEnabled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.quantaureumLookup != nil || v.externalChainSyncCommittee != nil
}

// SetStrictMode toggles fail-closed behavior for nil syncers.
// BRDG-FIX (2026-07-16): When true (production), the Verify* methods
// return an error instead of skipping verification when their respective
// syncer is nil. When false (test default), the legacy nil-safe skip
// behavior is preserved. Production startup MUST call SetStrictMode(true)
// after injecting both syncers.
func (v *BridgeHeaderVerifier) SetStrictMode(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.strictMode = enabled
}

// IsStrictMode returns true if strict (fail-closed) mode is enabled.
func (v *BridgeHeaderVerifier) IsStrictMode() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.strictMode
}

// HasQuantaureumLookup returns true if the Quantaureum header lookup is
// configured.
func (v *BridgeHeaderVerifier) HasQuantaureumLookup() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.quantaureumLookup != nil
}

// HasExternalChainSyncCommittee returns true if the external-chain sync
// committee verifier is configured. A configured verifier may still have no
// committee loaded; use IsExternalChainSyncCommitteeReady to check whether
// signature verification can actually run.
func (v *BridgeHeaderVerifier) HasExternalChainSyncCommittee() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.externalChainSyncCommittee != nil
}

// IsExternalChainSyncCommitteeReady returns true when an external-chain sync
// committee verifier is configured AND it reports an active (non-empty)
// committee. A checker that does not implement SyncCommitteeReadiness is
// assumed ready, since it may verify with an aggregate key instead of a
// member list.
//
// R3-02: mainnet strict mode previously accepted a non-nil verifier with an
// empty committee, so startup reported "strict mode ENABLED" while signature
// checks were silently skipped. Callers must treat ready=false as degraded:
// external-chain headers get hash/reorg checks only.
func (v *BridgeHeaderVerifier) IsExternalChainSyncCommitteeReady() bool {
	v.mu.RLock()
	sc := v.externalChainSyncCommittee
	v.mu.RUnlock()

	if sc == nil {
		return false
	}
	if readiness, ok := sc.(SyncCommitteeReadiness); ok {
		return readiness.HasActiveCommittee()
	}
	return true
}

// VerifyQuantaureumHeader verifies that a Quantaureum block at the given
// height has the expected hash. This detects chain reorganizations: if the
// chain reorged, the block at that height will have a different hash, and
// the message (which carries the old hash) will be rejected.
//
// Returns nil if the Quantaureum lookup is not configured (verification
// disabled). In production, the lookup MUST be configured for reorg protection.
//
// Returns an error if:
//   - blockHashHex is empty (message has no block hash)
//   - the header at blockNumber is not found (block was reorged away)
//   - the hash at blockNumber does not match blockHashHex (reorg detected)
func (v *BridgeHeaderVerifier) VerifyQuantaureumHeader(blockNumber uint64, blockHashHex string) error {
	v.mu.RLock()
	lookup := v.quantaureumLookup
	strict := v.strictMode
	v.mu.RUnlock()

	if lookup == nil {
		if strict {
			// BRDG-FIX (2026-07-16): fail-closed in production.
			// Silently skipping verification when the lookup is not
			// configured allows an attacker who can suppress syncer
			// initialization to bypass reorg detection entirely.
			return fmt.Errorf("quantaureum header lookup not configured (strict mode): cannot verify header at height %d (BRDG-)", blockNumber)
		}
		return nil // not configured, skip (test default)
	}

	if blockHashHex == "" {
		return fmt.Errorf("block hash is empty: cannot verify header at height %d", blockNumber)
	}

	header, err := lookup.GetHeaderByHeight(blockNumber)
	if err != nil {
		return fmt.Errorf("quantaureum header at height %d not found: %w (possible reorg)", blockNumber, err)
	}

	actualHash := block.ComputeBlockHash(header)
	expectedHex := strings.TrimPrefix(blockHashHex, "0x")
	actualHex := hex.EncodeToString(actualHash[:])
	if !strings.EqualFold(actualHex, expectedHex) {
		return fmt.Errorf("quantaureum block hash mismatch at height %d: expected %s, got %s (reorg detected)",
			blockNumber, expectedHex, actualHex)
	}
	return nil
}

// VerifyExternalChainHeader verifies an external-chain block header using sync
// committee signatures. The caller must provide the header (typically fetched
// via RPC). The header must be in QAU format; an Ethereum execution header has
// no SyncCommitteeSig/Bits fields and a populated QAU-format committee rejects
// it (Ethereum consensus requires a BLS12-381 verifier, R2-15).
//
// Returns nil if the external-chain sync committee is not configured
// (verification disabled). In production, the sync committee MUST be
// configured for header verification.
//
// Returns an error if:
//   - header is nil
//   - sync committee verification fails (insufficient signatures, invalid sig, etc.)
func (v *BridgeHeaderVerifier) VerifyExternalChainHeader(header *encoding.BlockHeader) error {
	v.mu.RLock()
	sc := v.externalChainSyncCommittee
	strict := v.strictMode
	v.mu.RUnlock()

	if sc == nil {
		if strict {
			// BRDG-FIX (2026-07-16): fail-closed in production.
			return fmt.Errorf("external-chain sync committee not configured (strict mode): cannot verify header (BRDG-)")
		}
		return nil // not configured, skip (test default)
	}
	if header == nil {
		return fmt.Errorf("external-chain header is nil")
	}
	return sc.VerifyBlockHeader(header)
}

// VerifyExternalChainHeaderByNumber fetches the external-chain block header at
// the given height via the provided HeaderFetcher, verifies its hash matches
// blockHashHex (reorg detection), and then passes the header to the sync
// committee checker.
//
// Verification steps:
//  1. Fetch the header from the external chain's RPC node
//  2. Verify the block hash matches what the message claims (reorg detection)
//  3. Ask the sync committee checker to verify the header. If the checker has
//     no committee loaded, it accepts QAU-format headers without sync committee
//     data as pre-committee blocks — i.e. no signature verification happens.
//     IsExternalChainSyncCommitteeReady reports that degraded state.
//
// Returns nil if the external-chain sync committee is not configured and
// strict mode is disabled (test default). In production (strict mode enabled),
// returns an error if the sync committee is not configured or if blockHashHex is empty
// (no legacy exemption for messages without a block hash).
func (v *BridgeHeaderVerifier) VerifyExternalChainHeaderByNumber(
	ctx context.Context,
	fetcher HeaderFetcher,
	blockNumber uint64,
	blockHashHex string,
) error {
	v.mu.RLock()
	sc := v.externalChainSyncCommittee
	strict := v.strictMode
	v.mu.RUnlock()

	if sc == nil {
		if strict {
			// BRDG-FIX (2026-07-16): fail-closed in production.
			return fmt.Errorf("external-chain sync committee not configured (strict mode): cannot verify header at height %d (BRDG-)", blockNumber)
		}
		return nil // not configured, skip (test default)
	}

	// BRDG-FIX (2026-07-16): In strict mode, require a non-empty
	// blockHashHex. Previously, an empty blockHashHex skipped the reorg
	// check entirely, allowing a message without a block hash to bypass
	// reorg detection even when the sync committee was configured. This
	// created an exploitable path: an attacker could submit a message
	// with BlockHash="" to skip reorg verification.
	if strict && blockHashHex == "" {
		return fmt.Errorf("block hash is empty (strict mode): cannot verify reorg at height %d (BRDG-)", blockNumber)
	}

	header, err := fetcher.FetchHeader(ctx, blockNumber)
	if err != nil {
		return fmt.Errorf("failed to fetch external chain header at height %d: %w", blockNumber, err)
	}

	// Step 1: Verify block hash matches (reorg detection).
	// In non-strict mode, preserve the legacy skip when blockHashHex is empty.
	if blockHashHex != "" {
		actualHash := block.ComputeBlockHash(header)
		expectedHex := strings.TrimPrefix(blockHashHex, "0x")
		actualHex := hex.EncodeToString(actualHash[:])
		if !strings.EqualFold(actualHex, expectedHex) {
			return fmt.Errorf("external chain block hash mismatch at height %d: expected %s, got %s (reorg detected)",
				blockNumber, expectedHex, actualHex)
		}
	}

	// Step 2: Verify sync committee signature (header validity).
	return sc.VerifyBlockHeader(header)
}

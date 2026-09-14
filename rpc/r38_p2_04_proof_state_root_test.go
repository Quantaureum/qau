// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// TestR38P2_04_GetProof_BindsBlockStateRoot is the RED-regression test
// for audit issue R38-P2-04
// (rpc/proof_api.go:43-91, 132-206,
// "eth_getProof returns a synthetic singleton-tree proof").
//
// Pre-fix behavior: GetProof discarded the requested block height
// (`_ = height`) and constructed a fresh single-entry Verkle tree from
// the current state — a malicious full node could fabricate any
// (address, balance, nonce) tuple and produce a cryptographically valid
// proof against that synthetic tree, with no canonical state root to
// compare against. Light clients / bridges that believed the proof was
// evidence of canonical state were misled.
//
// Post-fix behavior (rpc/proof_api.go:88-94, 117-119): the canonical
// StateRoot for the requested height is resolved via BlockReader and
// surfaced on AccountProofResult.StateRoot; an explicit Unverified=true
// flag warns the caller that the proof is NOT cryptographically bound
// to that state root (because buildAccountProof still builds a synthetic
// singleton tree rather than proving against canonical state).
//
// This test pins the three post-fix invariants:
//
//	(1) The StateRoot returned to the caller matches the StateRoot of
//	    the block at the requested height (no height-discard regression).
//	(2) Unverified is true — the proof's lack of cryptographic binding
//	    to StateRoot is explicitly surfaced, not silently omitted.
//	(3) StateRoot differs across heights — when the BlockReader returns
//	    blocks with different StateRoots at heights 5 and 10, GetProof
//	    for height=5 returns block5.StateRoot and GetProof for height=10
//	    returns block10.StateRoot; a pre-fix bug returned "" for both.
func TestR38P2_04_GetProof_BindsBlockStateRoot(t *testing.T) {
	cases := []struct {
		name         string
		height       string
		wantRoot     types.Hash
		wantNonEmpty bool
	}{
		{
			name:         "explicit_height_5_returns_canonical_state_root",
			height:       "5",
			wantRoot:     types.Hash{0xAA, 0x55, 0x00, 0x00},
			wantNonEmpty: true,
		},
		{
			name:         "explicit_height_10_returns_distinct_canonical_state_root",
			height:       "10",
			wantRoot:     types.Hash{0xBB, 0x66, 0x11, 0x11},
			wantNonEmpty: true,
		},
	}

	br := &r38P2_04BlockReader{}
	sr := &r38P2_04StateReader{balance: big.NewInt(1_000_000_000_000), nonce: 42}
	api := NewProofAPI(br, sr)

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			// Cast the wantRoot into the 0x-prefixed hex that
			// AccountProofResult.StateRoot uses (matches what BlockResponse
			// serialized StateRoot fields emit). buildAccountProof doesn't
			// alter the StateRoot string, so we expect exactly what
			// BlockResponse.StateRoot returned (already 0x-prefixed hex).
			wantRootStr := "0x" + tc.wantRoot.String()
			_ = wantRootStr

			result, err := api.GetProof("0x1234567890abcdef1234567890abcdef12345678", nil, tc.height)
			if err != nil {
				t.Fatalf("GetProof: %v", err)
			}
			if result == nil {
				t.Fatalf("GetProof returned nil result")
			}
			if tc.wantNonEmpty && result.StateRoot == "" {
				t.Fatalf("R38-P2-04 REGRESSION: StateRoot empty for height=%s — the canonical block-guided state-root exposure is missing or the BlockReader path was reverted", tc.height)
			}
			if result.StateRoot != wantRootStr {
				t.Fatalf("StateRoot mismatch: got %q, want %q for height=%s — block-height-to-state-root wiring broken (regression of R38-P2-04 fix)", result.StateRoot, wantRootStr, tc.height)
			}
			if !result.Unverified {
				t.Fatalf("R38-P2-04 REGRESSION: Unverified=false — the buildAccountProof synthetic-tree warning MUST be surfaced true until the StateReader exposes a stateRoot-aware Prove; false silences callers into trusting a non-binding proof")
			}
		})
	}
}

// TestR38P2_04_GetProof_BlockReaderErrorLeavesStateRootEmpty pins the
// graceful-degradation path: when the BlockReader cannot resolve a block
// for the requested height (e.g. requesting height=999999 on a
// testnet at height 100), StateRoot returns "" (empty string) without
// panicking — the prior canonical-state-root flow must not fail-closed
// by inventing a fake root, nor fail-OPEN by forcing callers to trust
// the unbound proof silently.
//
// Combined with the canonical-root test above this forms the two-sided
// invariant under R38-P2-04 in the conservative-mitigation phase:
//   - StateRoot is authoritative when available.
//   - When unavailable, the gap is honest (empty + Unverified=true).
func TestR38P2_04_GetProof_BlockReaderErrorLeavesStateRootEmpty(t *testing.T) {
	br := &r38P2_04BlockReader{}
	sr := &r38P2_04StateReader{}
	api := NewProofAPI(br, sr)

	// r38P2_04BlockReader returns "block not found" for heights > 9999.
	result, err := api.GetProof("0x1234567890abcdef1234567890abcdef12345678", nil, "999999")
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if result == nil {
		t.Fatalf("GetProof returned nil result")
	}
	if result.StateRoot != "" {
		t.Fatalf("BlockReader missing-block path must surface StateRoot=\"\", got %q — the conservative mitigation must not invent a state root when the canonical block can't be resolved", result.StateRoot)
	}
	if !result.Unverified {
		t.Fatalf("Unverified must be true even when BlockReader cannot resolve the canonical root — caller trust must not be silently re-enabled")
	}
}

// r38P2_04BlockReader is a minimal BlockReader for the proof_api test.
// It returns canned *BlockResponse values for heights 5 and 10 with
// distinct StateRoots so the R38-P2-04 wiring can be exercised
// deterministically without a full DB.
type r38P2_04BlockReader struct{}

func (br *r38P2_04BlockReader) GetBlockByHash(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04BlockReader) GetBlockByHeight(height uint64) (any, error) {
	switch height {
	case 5:
		return &BlockResponse{StateRoot: "0x" + types.Hash{0xAA, 0x55, 0x00, 0x00}.String()}, nil
	case 10:
		return &BlockResponse{StateRoot: "0x" + types.Hash{0xBB, 0x66, 0x11, 0x11}.String()}, nil
	default:
		return nil, errBlockNotFound()
	}
}
func (br *r38P2_04BlockReader) GetLatestHeight() uint64 { return 5 }
func (br *r38P2_04BlockReader) GetTransaction(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04BlockReader) GetTransactionReceipt(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04BlockReader) GetBlockByHeightRange(from, to uint64) ([]any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04BlockReader) GetGasLimit() uint64 { return 30_000_000 }

// r38P2_04StateReader is a minimal StateReader — just enough to satisfy
// NewProofAPI; the proof-encoding values are deterministic so the test
// doesn't depend on StateReader semantics for the StateRoot/Unverified
// invariant.
type r38P2_04StateReader struct {
	balance *big.Int
	nonce   uint64
}

func (sr *r38P2_04StateReader) GetBalance(addr types.Address) *big.Int {
	if sr.balance == nil {
		return new(big.Int)
	}
	return sr.balance
}
func (sr *r38P2_04StateReader) GetNonce(addr types.Address) uint64 { return sr.nonce }
func (sr *r38P2_04StateReader) GetCode(addr types.Address) []byte  { return nil }
func (sr *r38P2_04StateReader) GetState(addr types.Address, key types.Hash) types.Hash {
	return types.Hash{}
}
func (sr *r38P2_04StateReader) IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool) {
	// No-op for the test.
}

// R38-P2-04 DEEP FIX (2026-08-02): StateReader interface gained three
// stateRoot-aware proof methods. The mock has no real state trie behind
// it, so all three return the honest "not supported" errors and zero
// StateRoot — the test asserts the conservative fallback path remains
// honest about not being cryptographically bound.
func (sr *r38P2_04StateReader) StateRoot() types.Hash { return types.Hash{} }
func (sr *r38P2_04StateReader) ProveAccount(addr types.Address) (*trie.VerkleProof, error) {
	return nil, ErrProofNotSupported
}
func (sr *r38P2_04StateReader) ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error) {
	return nil, ErrProofNotSupported
}

// errBlockNotFound is a tiny sentinel-error helper kept inline to avoid
// importing "errors" just for two panic messages.
func errBlockNotFound() error { return &r38P2_04Err{"block not found"} }

type r38P2_04Err struct{ msg string }

func (e *r38P2_04Err) Error() string { return e.msg }

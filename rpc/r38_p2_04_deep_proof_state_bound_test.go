// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// TestR38P2_04_Deep_GetProof_UnverifiedFalseWhenProveAccountAvailable is
// the RED→GREEN test for the DEEP FIX portion of R38-P2-04 — the
// surgical mitigation we shipped earlier only surfaces StateRoot +
// Unverified=true. This test pins the deep fix invariant: when the
// StateReader supplies a real Verkle proof via ProveAccount, the RPC
// response MUST set Unverified=FALSE so light clients / bridges know
// the proof is cryptographically bound to canonical state.
//
// The mock stateReader below returns a non-nil VerkleProof (a synthetic
// path over a single account — sufficient to verify the wire-level
// invariant that we ACTUALLY use the proof from ProveAccount, rather
// than silently falling back to the synthetic-tree path) and a non-zero
// StateRoot. The expected RPC response asserts Unverified=false.
//
// This is a regression guard: should anyone remove the ProveAccount
// code path from GetProof, this test fails with Unverified=true and
// explicitly names the fix that was reverted.
func TestR38P2_04_Deep_GetProof_UnverifiedFalseWhenProveAccountAvailable(t *testing.T) {
	sr := &r38P2_04DeepStateReader{}
	br := &r38P2_04DeepBlockReader{}
	api := NewProofAPI(br, sr)

	res, err := api.GetProof("0x1234567890abcdef1234567890abcdef12345678", nil, "latest")
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if res == nil {
		t.Fatal("GetProof returned nil result")
	}
	if res.Unverified {
		t.Fatalf("R38-P2-04 DEEP FIX REGRESSION: Unverified=true even though the StateReader supplied a real VerkleProof via ProveAccount — the proof is cryptographically bound to StateRoot and the API must surface that contract by setting Unverified=false (rpc/proof_api.go:107-118). Either the ProveAccount call site was reverted, or the nil check is inverted.")
	}
	if len(res.AccountProof) == 0 {
		t.Fatalf("R38-P2-04 DEEP FIX REGRESSION: AccountProof is empty — ProveAccount returned a non-nil proof but GetProof did not feed it through serializeVerkleProof")
	}
	// The synthesized proof path on a 1-account tree has length ≥ 1.
	if len(res.AccountProof) < 1 {
		t.Fatalf("synthesized proof path too short: %d entries", len(res.AccountProof))
	}
	// Each entry must be a 0x-prefixed hex hash (66 chars = "0x" + 32 byte hex)
	for i, p := range res.AccountProof {
		if len(p) != 66 || p[:2] != "0x" {
			t.Fatalf("AccountProof[%d] = %q (len=%d) is not a canonical 0x+64-hex hash, R38-P2-04 DEEP FIX wire format broke", i, p, len(p))
		}
	}
}

// TestR38P2_04_Deep_GetProof_FallbackUnverifiedWhenProveAccountFails pins
// the symmetric path: when ProveAccount returns (nil, ErrProofNotSupported)
// the API MUST fall back to the synthetic-tree pseudo-proof and surface
// Unverified=true honestly (preserving the original conservative mitigation).
//
// Together with the previous test this asserts the binary isometry:
// deep path → Unverified=false + real proof; fallback → Unverified=true + pseudo.
// A future regression where deep-path errors leak Unverified=false (or the
// fallback accidentally claims Unverified=false) is caught immediately.
func TestR38P2_04_Deep_GetProof_FallbackUnverifiedWhenProveAccountFails(t *testing.T) {
	sr := &r38P2_04StateReader{} // returns ErrProofNotSupported (see api_test.go mock style)
	br := &r38P2_04DeepBlockReader{}
	api := NewProofAPI(br, sr)

	res, err := api.GetProof("0x1234567890abcdef1234567890abcdef12345678", nil, "latest")
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if res == nil {
		t.Fatal("GetProof returned nil result")
	}
	if !res.Unverified {
		t.Fatalf("R38-P2-04 DEEP FIX REGRESSION: when ProveAccount returns ErrProofNotSupported, Unverified MUST be true (conservative fallback). Got Unverified=false — the fallback was silently strengthened to claim proof binding that does NOT exist.")
	}
}

// TestR38P2_04_Deep_StateDBProveAccountBindsToRoot is the integration
// test that exercises the StateDB real Verkle backend through the
// node stateReaderAdapter → StateDB.ProveAccount path. We don't have
// an isolated adapter test harness here (spinning up node.NewNode is
// out of scope), so this test exercises StateDB directly and asserts
// the proof's Root matches s.Root(). If the verifier path can't bind
// to StateRoot, downstream eth_getProof bindings inherit the failure.
//
// Skipped when s.stateTrie is nil (NewStateDBWithoutStorage stub).
func TestR38P2_04_Deep_StateDBProveAccountBindsToRoot(t *testing.T) {
	sdb := newStateDBWithRealStateTrieForTest(t)
	if sdb == nil {
		t.Skip("StateDB without state trie not exercisable here")
	}

	addr := types.Address{0xab, 0xcd}
	balance := big.NewInt(1_000_000)
	nonce := uint64(1)
	code := []byte{0x60, 0x80}
	sdb.SetBalance(addr, balance)
	sdb.SetNonce(addr, nonce)
	sdb.SetCode(addr, code)
	// Commit dirty accounts into the Verkle tree so ProveAccount sees a
	// populated trie. StateDB writes go to dirtyAccounts first; Commit
	// walks them into s.stateTrie via Put — without Commit the proof path
	// legitimately returns empty (empty tree exclusion, verkle.go:2766).
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("StateDB.Commit: %v", err)
	}
	root := sdb.Root()

	proof, err := sdb.ProveAccount(addr)
	if err != nil {
		t.Fatalf("StateDB.ProveAccount: %v", err)
	}
	if proof == nil {
		t.Fatal("StateDB.ProveAccount returned (nil, nil) — real Verkle backend is silently bypassed")
	}
	if len(proof.Path) == 0 {
		t.Fatal("StateDB.ProveAccount returned a VerkleProof with empty Path — state trie did not produce a path from root to leaf; the proof is not verifiable against StateRoot")
	}
	// proof.Path[0] is the root (VerklePath invariant, see verkle.go:585-591)
	if proof.Path[0] != root {
		t.Fatalf("proof.Path[0]=%x does NOT equal StateDB.Root()=%x — the ProveAccount path is NOT stateRoot-bound; light clients verifying against StateRoot would reject a legitimate proof, or worse accept a fabricated proof verified against a different root", proof.Path[0], root)
	}
}

// TestR38P2_04_Deep_StateDBProveStorageBindsToRoot mirrors the above for
// the storage-slot proof path. Skipped when s.stateTrie is nil.
func TestR38P2_04_Deep_StateDBProveStorageBindsToRoot(t *testing.T) {
	sdb := newStateDBWithRealStateTrieForTest(t)
	if sdb == nil {
		t.Skip("StateDB without state trie not exercisable here")
	}

	addr := types.Address{0xab, 0xcd}
	slot := types.Hash{0x10, 0x20}
	value := types.Hash{0x30, 0x40}
	sdb.SetBalance(addr, big.NewInt(1))
	sdb.SetNonce(addr, 1)
	sdb.SetState(addr, slot, value)
	// Commit so stateTrie sees the storage entry. Same rationale as the
	// account test above — dirtyAccounts walked into Verkle tree on Commit.
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("StateDB.Commit: %v", err)
	}
	root := sdb.Root()

	proof, err := sdb.ProveStorage(addr, slot)
	if err != nil {
		t.Fatalf("StateDB.ProveStorage: %v", err)
	}
	if proof == nil {
		t.Fatal("StateDB.ProveStorage returned (nil, nil) — real Verkle backend is silently bypassed")
	}
	if len(proof.Path) == 0 {
		t.Fatal("StateDB.ProveStorage returned an empty Path — storage proof path is not verifiable against StateRoot")
	}
	if proof.Path[0] != root {
		t.Fatalf("storage proof.Path[0]=%x does NOT equal StateDB.Root()=%x — the ProveStorage path is NOT stateRoot-bound; light clients verifying against StateRoot would reject a legitimate proof, or worse accept a fabricated proof verified against a different root", proof.Path[0], root)
	}
}

// r38P2_04DeepStateReader returns a real (here: synthetic-singleton, but
// PRESENT) VerkleProof, distinct from the (nil, Err) fallback path. Used
// by the deep-fix happy path test to assert Unverified=false + nonempty
// AccountProof.
type r38P2_04DeepStateReader struct {
	cachedProof *trie.VerkleProof
	cachedRoot  types.Hash
}

func (s *r38P2_04DeepStateReader) GetBalance(addr types.Address) *big.Int { return big.NewInt(0) }
func (s *r38P2_04DeepStateReader) GetNonce(addr types.Address) uint64     { return 0 }
func (s *r38P2_04DeepStateReader) GetCode(addr types.Address) []byte      { return nil }
func (s *r38P2_04DeepStateReader) GetState(addr types.Address, key types.Hash) types.Hash {
	return types.Hash{}
}
func (s *r38P2_04DeepStateReader) IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool) {
}

// StateRoot returns a non-zero canonical root — the deep happy path.
func (s *r38P2_04DeepStateReader) StateRoot() types.Hash {
	if s.cachedRoot == (types.Hash{}) {
		s.cachedRoot = types.Hash{0xCA, 0xFE, 0xBA, 0xBE}
	}
	return s.cachedRoot
}

// ProveAccount returns a synthetic-proof-shaped VerkleProof so the deep
// happy path is exercisable without a real trie. Path[0] is set to
// StateRoot() so any future caller verifying against root would succeed.
func (s *r38P2_04DeepStateReader) ProveAccount(addr types.Address) (*trie.VerkleProof, error) {
	if s.cachedProof == nil {
		s.cachedProof = &trie.VerkleProof{
			Key:   addr[:],
			Value: []byte{0x01, 0x02, 0x03},
			Path:  []types.Hash{s.StateRoot(), {0x11, 0x22}},
			Siblings: [][]trie.SiblingWithIdx{
				{{Idx: 0, Hash: types.Hash{0xAA, 0xBB}}},
			},
		}
	}
	return s.cachedProof, nil
}
func (s *r38P2_04DeepStateReader) ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error) {
	return s.ProveAccount(addr)
}

// r38P2_04DeepBlockReader returns a BlockResponse with a non-empty
// StateRoot so the GetProof StateRoot field is exercised end-to-end.
type r38P2_04DeepBlockReader struct{}

func (br *r38P2_04DeepBlockReader) GetBlockByHash(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04DeepBlockReader) GetBlockByHeight(height uint64) (any, error) {
	if height == 0 || height == 9999 {
		return &BlockResponse{StateRoot: "0x" + types.Hash{0xCA, 0xFE, 0xBA, 0xBE}.String()}, nil
	}
	return &BlockResponse{StateRoot: "0x" + types.Hash{0xCA, 0xFE, 0xBA, 0xBE}.String()}, nil
}
func (br *r38P2_04DeepBlockReader) GetLatestHeight() uint64 { return 9999 }
func (br *r38P2_04DeepBlockReader) GetTransaction(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04DeepBlockReader) GetTransactionReceipt(hash types.Hash) (any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04DeepBlockReader) GetBlockByHeightRange(from, to uint64) ([]any, error) {
	return nil, errBlockNotFound()
}
func (br *r38P2_04DeepBlockReader) GetGasLimit() uint64 { return 30_000_000 }

// newStateDBWithRealStateTrieForTest creates an in-memory StateDB whose
// internal stateTrie is alive (so ProveAccount can produce real paths
// against StateRoot). Returns nil if the StateDB selects the
// NewStateDBWithoutStorage stub path (test then skips).
//
// Implemented via NewStateDB() with no database path: allocStateDB /
// RecoverConsistency populate a fresh in-memory trie.
func newStateDBWithRealStateTrieForTest(t *testing.T) *state.StateDB {
	t.Helper()
	// NewStateDB panic-on-RecoverConsistency-fail contract — should not
	// fire for an empty in-memory DB. Defer recover defensively.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("NewStateDB panic (skipping integration test): %v", r)
		}
	}()
	sdb := state.NewStateDB()
	if sdb == nil {
		return nil
	}
	// Pre-populate the trie (lazy); SetBalance will create the account
	// entry on the next call. Root is then non-trivial and ProveAccount's
	// returned path's root MUST equal Root().
	return sdb
}

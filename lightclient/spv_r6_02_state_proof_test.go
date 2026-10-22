// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// R6-02 (2026-10-21 sixth-round audit): the state-proof path used to be built
// out of StateDB.GetAccountWithProof/GetStateWithProof, whose VerkleProof.Proof
// is the literal placeholder `[][]byte{}, // Simplified`. Nothing downstream
// could verify it, storage lookups that failed were swallowed by `continue`, and
// the account was read from the dirty overlay rather than the proved leaf. These
// tests pin the replacement contract: proofs come from the canonical trie, are
// bound to the live state root, describe the proved leaf, and every inability to
// prove is an error instead of a pseudo-proof.

func newProvedStateDB(t *testing.T) (*state.StateDB, types.Hash) {
	t.Helper()

	sdb := state.NewStateDB()
	addr := types.Address{0xa1, 0xb2}
	sdb.SetBalance(addr, big.NewInt(1_000_000))
	sdb.SetNonce(addr, 7)
	// Storage is deliberately set on the funded account as well: R6-05 shows
	// that committing it does NOT put it in the state trie, so the prover must
	// refuse to speak about it.
	sdb.SetState(addr, types.Hash{0x10, 0x20}, types.Hash{0x30, 0x40})
	if _, err := sdb.Commit(1); err != nil {
		t.Fatalf("StateDB.Commit: %v", err)
	}
	root := sdb.Root()
	if root == (types.Hash{}) {
		t.Fatal("committed state has a zero root — fixture is broken")
	}
	return sdb, root
}

// putTipBlock stores a minimal height-1 block whose header commits to stateRoot.
func putTipBlock(t *testing.T, stateRoot types.Hash) *block.BlockStore {
	t.Helper()

	bs := block.NewBlockStore(db.NewMemDB())
	blk := &encoding.Block{Header: &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Slot:      1,
		StateRoot: stateRoot,
	}}
	if err := bs.PutBlockWithIndex(blk); err != nil {
		t.Fatalf("PutBlockWithIndex: %v", err)
	}
	return bs
}

func TestR6_02_AccountProofIsBoundToTheLiveRoot(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	prover := NewSPVProver(nil, sdb)

	proof, err := prover.GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof: %v", err)
	}
	if proof.AccountProof == nil {
		t.Fatal("nil AccountProof")
	}
	if !bytes.Equal(proof.AccountProof.Key, addr[:]) {
		t.Fatalf("AccountProof.Key = %x, want the queried address %x", proof.AccountProof.Key, addr[:])
	}
	if len(proof.AccountProof.Path) == 0 {
		t.Fatal("AccountProof.Path is empty — the proof carries no path from the state root, which is the R6-02 placeholder shape")
	}
	if proof.AccountProof.Path[0] != root {
		t.Fatalf("AccountProof.Path[0] = %x, want the live state root %x", proof.AccountProof.Path[0], root)
	}
	if proof.Account == nil {
		t.Fatal("a funded account must come back from the proved leaf, got nil")
	}
	if proof.Account.Balance.Cmp(big.NewInt(1_000_000)) != 0 || proof.Account.Nonce != 7 {
		t.Fatalf("proved account = (balance %v, nonce %d), want (1000000, 7)", proof.Account.Balance, proof.Account.Nonce)
	}
	if !VerifyStateProof(root, proof) {
		t.Fatal("VerifyStateProof must accept a proof generated against the same root")
	}
	if VerifyStateProof(types.Hash{0xff}, proof) {
		t.Fatal("VerifyStateProof accepted a proof against a foreign root")
	}

	v := NewSPVVerifier()
	if !v.VerifyAccountExists(root, addr, proof) {
		t.Fatal("VerifyAccountExists rejected a valid inclusion proof")
	}
	if !v.VerifyAccountBalance(root, addr, big.NewInt(1_000_000), proof) {
		t.Fatal("VerifyAccountBalance rejected the proved balance")
	}
	if v.VerifyAccountBalance(root, addr, big.NewInt(999), proof) {
		t.Fatal("VerifyAccountBalance accepted a balance that is not the proved one")
	}
}

func TestR6_02_TipHeaderMustAgreeWithTheLiveRoot(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}

	// A header that commits to a different root means the block store and the
	// state backend disagree; attaching the disagreement to a proof would let a
	// light client verify the state against the wrong block.
	prover := NewSPVProver(putTipBlock(t, types.Hash{0x01, 0x02, 0x03}), sdb)
	if _, err := prover.GenerateStateProof(addr, nil); !errors.Is(err, ErrInvalidStateProof) {
		t.Fatalf("GenerateStateProof with a mismatched tip header = %v, want ErrInvalidStateProof", err)
	}

	// Matching header: the proof carries it.
	prover = NewSPVProver(putTipBlock(t, root), sdb)
	proof, err := prover.GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof with a matching tip header: %v", err)
	}
	if proof.BlockHeader == nil || proof.BlockHeader.StateRoot != root {
		t.Fatalf("BlockHeader = %+v, want the header committing to %x", proof.BlockHeader, root)
	}
}

func TestR6_02_NoBackendIsAFailureNotAnEmptyProof(t *testing.T) {
	// stateDB == nil is "this node has no state", which the light client must
	// see as an error, never as a proof of absence.
	if _, err := NewSPVProver(nil, nil).GenerateStateProof(types.Address{0x01}, nil); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("GenerateStateProof without a state backend = %v, want ErrStateNotFound", err)
	}
	if _, err := NewSPVProver(nil, nil).GenerateMultiStateProof([]types.Address{{0x01}}, nil); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("GenerateMultiStateProof without a state backend = %v, want ErrStateNotFound", err)
	}
}

// TestR6_02_AbsentAccountIsProvableAbsence pins the other half of the contract:
// an address that is not in state comes back as a verified exclusion proof with
// Account == nil, so "absent" is a cryptographic claim and not an RPC error, and
// not a silently empty success either.
func TestR6_02_AbsentAccountIsProvableAbsence(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	absent := types.Address{0xde, 0xad, 0xbe, 0xef}

	proof, err := NewSPVProver(nil, sdb).GenerateStateProof(absent, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof for an absent account: %v", err)
	}
	if proof.Account != nil {
		t.Fatalf("an exclusion proof carries account data: %+v", proof.Account)
	}
	if !proof.AccountProof.IsExclusion {
		t.Fatal("the prover reported an absent account with an inclusion proof")
	}
	if !VerifyStateProof(root, proof) {
		t.Fatal("VerifyStateProof rejected the node's own exclusion proof")
	}
	if VerifyStateProof(types.Hash{0x01}, proof) {
		t.Fatal("VerifyStateProof accepted the exclusion proof against a foreign root")
	}
	v := NewSPVVerifier()
	if v.VerifyAccountExists(root, absent, proof) {
		t.Fatal("VerifyAccountExists claimed an account that state says is absent")
	}
	if !v.VerifyAccountExists(root, types.Address{0xa1, 0xb2}, mustProve(t, sdb, types.Address{0xa1, 0xb2})) {
		t.Fatal("VerifyAccountExists rejected the funded account")
	}
}

func mustProve(t *testing.T, sdb *state.StateDB, addr types.Address) *StateProof {
	t.Helper()
	proof, err := NewSPVProver(nil, sdb).GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof(%x): %v", addr[:4], err)
	}
	return proof
}

// TestR6_02_PlaceholderProofIsRejected documents why the old code path was
// broken: the proof GetAccountWithProof used to hand out cannot be verified
// against any root, so no consumer of VerifyStateProof could trust it.
func TestR6_02_PlaceholderProofIsRejected(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}

	_, legacy, err := sdb.GetAccountWithProof(addr)
	if err != nil {
		t.Fatalf("GetAccountWithProof: %v", err)
	}
	if len(legacy.Proof) != 0 || len(legacy.Path) != 0 {
		t.Fatalf("fixture drift: GetAccountWithProof no longer returns the placeholder shape (%d Proof, %d Path)",
			len(legacy.Proof), len(legacy.Path))
	}
	placeholder := &StateProof{
		Address:      addr,
		Account:      &state.Account{Nonce: 7, Balance: big.NewInt(1_000_000)},
		AccountProof: legacy,
	}
	if VerifyStateProof(root, placeholder) {
		t.Fatal("VerifyStateProof accepted the [][]byte{} placeholder — a light client would have trusted a proof that carries no path at all")
	}
	if NewSPVVerifier().VerifyAccountExists(root, addr, placeholder) {
		t.Fatal("VerifyAccountExists accepted the placeholder proof")
	}
}

func TestR6_02_AddressBindingIsEnforced(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}

	proof, err := NewSPVProver(nil, sdb).GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof: %v", err)
	}
	if !VerifyStateProof(root, proof) {
		t.Fatal("baseline proof must verify before the tampering cases run")
	}

	// Re-addressing a valid proof to a different account must fail: the path is
	// for the original key, not the claimed address.
	other := *proof
	other.Address = types.Address{0xc3, 0xd4}
	if VerifyStateProof(root, &other) {
		t.Fatal("VerifyStateProof accepted a proof re-labeled with another address")
	}

	// A proof envelope claiming a storage entry that is not bound to the
	// (address, slot) pair it reports must fail even when the account path is
	// perfectly valid.
	key := types.Hash{0x10, 0x20}
	other.Address = addr
	other.StorageProofs = map[types.Hash]*StorageProofEntry{
		key: {
			Key: key,
			// Bound to a DIFFERENT slot than the one being claimed.
			Proof: &trie.VerkleProof{Key: state.StorageProofKey(addr, types.Hash{0x99})},
		},
	}
	if VerifyStateProof(root, &other) {
		t.Fatal("VerifyStateProof accepted a storage entry bound to another slot")
	}

	// Same, but carrying no proof material at all.
	other.StorageProofs = map[types.Hash]*StorageProofEntry{key: {Key: key}}
	if VerifyStateProof(root, &other) {
		t.Fatal("VerifyStateProof accepted a storage entry with a nil proof")
	}
	if VerifyStateProof(root, nil) || VerifyStateProof(root, &StateProof{}) {
		t.Fatal("VerifyStateProof accepted a nil or empty envelope")
	}
}

// TestR6_05_StorageSlotRequestsAreRefused pins the honest half of the storage
// finding: committed storage never reaches the Verkle state trie, so the node
// cannot produce a state-root-bound storage proof and must say so instead of
// returning an exclusion proof next to a non-zero value.
func TestR6_05_StorageSlotRequestsAreRefused(t *testing.T) {
	sdb, _ := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	slot := types.Hash{0x10, 0x20}
	want := types.Hash{0x30, 0x40}

	// The node can READ the slot back — the value is committed, it simply is not
	// in the thing the proof is generated from.
	if got := sdb.GetState(addr, slot); got != want {
		t.Fatalf("fixture drift: GetState = %x, want %x", got[:4], want[:4])
	}

	// And ProveStorage proves its ABSENCE from the state trie, which is exactly
	// the contradiction that must not be shipped to a light client.
	storageProof, err := sdb.ProveStorage(addr, slot)
	if err != nil {
		t.Fatalf("ProveStorage: %v", err)
	}
	if !storageProof.IsExclusion {
		t.Fatal("committed storage is now part of the state trie — relax the refusal in GenerateStateProof, the per-entry Unverified label in rpc/proof_api.go and this test together")
	}

	prover := NewSPVProver(nil, sdb)
	if _, err := prover.GenerateStateProof(addr, []types.Hash{slot}); !errors.Is(err, ErrProofNotSupported) {
		t.Fatalf("GenerateStateProof with a storage key = %v, want ErrProofNotSupported", err)
	}
	if _, err := prover.GenerateMultiStateProof([]types.Address{addr}, map[types.Address][]types.Hash{addr: {slot}}); !errors.Is(err, ErrProofNotSupported) {
		t.Fatalf("GenerateMultiStateProof with a storage key = %v, want ErrProofNotSupported", err)
	}

	// Without storage keys the account proof still works (the refusal is scoped
	// to the claim that cannot be honored).
	if _, err := prover.GenerateStateProof(addr, nil); err != nil {
		t.Fatalf("GenerateStateProof without storage keys: %v", err)
	}
}

// TestR6_05_GenerateMultiStateProofPropagatesFailures pins the removal of the
// "Skip accounts that can't be found" continue: a short list is not allowed to
// look like a statement about chain state.
func TestR6_05_GenerateMultiStateProofPropagatesFailures(t *testing.T) {
	sdb, _ := newProvedStateDB(t)
	bad := types.Address{0xee}
	slot := types.Hash{0x01}

	if _, err := NewSPVProver(nil, sdb).GenerateMultiStateProof(
		[]types.Address{{0xa1, 0xb2}, bad},
		map[types.Address][]types.Hash{bad: {slot}},
	); !errors.Is(err, ErrProofNotSupported) {
		t.Fatalf("GenerateMultiStateProof = %v, want the refused account to abort the batch", err)
	}

	proofs, err := NewSPVProver(nil, sdb).GenerateMultiStateProof([]types.Address{{0xa1, 0xb2}, bad}, nil)
	if err != nil {
		t.Fatalf("GenerateMultiStateProof without storage keys: %v", err)
	}
	if len(proofs) != 2 {
		t.Fatalf("got %d proofs, want one per requested address", len(proofs))
	}
}

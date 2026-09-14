// Quantaureum Node source, version 1.0.0.
// R39-P1-02 (2026-08-02) regression tests.
//
// R38-P0-01 audit half-migration left CreateProposal trusting
// `proposal.Hash` verbatim from the caller, and ApproveProposal signing
// over that client-supplied hash without re-deriving
// ComputeMultisigV2ProposalHash over the proposal's fields. R39-P1-02 adds:
//   - Proposal.ChainID / Proposal.Nonce / Proposal.HashWalletAddr fields
//     so the store can recompute the canonical hash.
//   - MultisigStateStore.CreateProposal rejects any proposal whose
//     recomputed canonical hash != proposal.Hash (fail-closed at the
//     single chokepoint — every caller is held to the same invariant).
//   - rpc.ApproveProposal re-asserts the invariant at the signing boundary
//     (defense-in-depth).
//
// These white-box tests pin the store-side gate; the RPC black-box path is
// covered by TestR4KEYS01_ApproveProposalWithRealPubKey (which exercises a
// legitimate round-trip through the new gate).
package multisig

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r39P102Wallet creates + registers a wallet the test can attach proposals
// to. Returns the wallet address (used as the V1 cache key in the store).
func r39P102Wallet(t *testing.T, store *MultisigStateStore) types.Address {
	t.Helper()
	addr := types.Address{0x0A, 0x0B, 0x0C}
	signers := []SignerInfo{{PublicKey: make([]byte, 32), Alias: addr.String()}}
	cfg := &WalletConfig{
		Address:   addr,
		Signers:   signers,
		Threshold: 1,
		CreatedAt: 1,
	}
	if err := store.RegisterWallet(cfg); err != nil {
		t.Fatalf("RegisterWallet: %v", err)
	}
	return addr
}

// makeCanonicalProposal builds a Proposal whose Hash is the canonical
// ComputeMultisigV2ProposalHash output over its fields. The hash input
// uses `wallet` for the wallet-position (HashWalletAddr), matching what
// VerifyProposalHash recomputes.
func makeCanonicalProposal(t *testing.T, chainID uint64, wallet, to types.Address, value *big.Int, data []byte, nonce, expiresAt uint64) *Proposal {
	t.Helper()
	h, err := types.ComputeMultisigV2ProposalHash(chainID, wallet, to, value, data, nonce, expiresAt)
	if err != nil {
		t.Fatalf("ComputeMultisigV2ProposalHash: %v", err)
	}
	return &Proposal{
		Hash:           h,
		WalletAddr:     wallet, // V1 path: cache key == hash wallet
		HashWalletAddr: wallet,
		To:             to,
		Value:          value,
		Data:           data,
		ExpiresAt:      int64(expiresAt),
		ChainID:        chainID,
		Nonce:          nonce,
	}
}

// TestR39_P1_02_CreateProposal_AcceptsCanonicalHash verifies that a
// Proposal whose Hash equals the canonical recomputed hash is accepted by
// the store. This is the "happy path" the RPC and V2 precompile both
// produce, and is the precondition for any legitimate proposal flow.
func TestR39_P1_02_CreateProposal_AcceptsCanonicalHash(t *testing.T) {
	store := NewMultisigStateStore()
	wallet := r39P102Wallet(t, store)
	to := types.Address{0x0F}

	p := makeCanonicalProposal(t, 1668, wallet, to, big.NewInt(100), nil, 0x0102030405, 9_999)
	walletConfig := store.GetWallet(wallet)
	if walletConfig == nil {
		t.Fatal("wallet not registered")
	}
	if err := store.CreateProposal(p, walletConfig); err != nil {
		t.Fatalf("CreateProposal MUST accept a canonical-hash proposal, got: %v", err)
	}
	got := store.GetProposal(p.Hash)
	if got == nil || got.Hash != p.Hash {
		t.Fatal("GetProposal returned wrong proposal")
	}
}

// TestR39_P1_02_CreateProposal_RejectsMismatchedHash verifies the store
// gate's fail-closed posture: a Proposal whose Hash is NOT the canonical
// recomputed hash is REJECTED, regardless of whether the wallet is
// registered. This is the structural closure of the R39-P1-02 finding
// (CreateProposal trusted proposal.Hash verbatim, letting a caller store a
// proposal with an arbitrary 32-byte hash that ApproveProposal would later
// sign over).
func TestR39_P1_02_CreateProposal_RejectsMismatchedHash(t *testing.T) {
	store := NewMultisigStateStore()
	wallet := r39P102Wallet(t, store)
	to := types.Address{0x0F}

	// Build a canonical proposal, then flip ONE bit of the stored Hash so
	// it no longer matches the recomputed canonical hash of the fields.
	p := makeCanonicalProposal(t, 1668, wallet, to, big.NewInt(100), nil, 0x0102030405, 9_999)
	p.Hash[0] ^= 0x01 // tampered hash

	walletConfig := store.GetWallet(wallet)
	if err := store.CreateProposal(p, walletConfig); err == nil {
		t.Fatal("CreateProposal MUST reject a proposal whose Hash != canonical hash of fields (R39-P1-02 invariant)")
	}
	// And the tampered proposal must NOT be persisted.
	if got := store.GetProposal(p.Hash); got != nil {
		t.Fatal("tampered-hash proposal was persisted — invariant gate leak")
	}
}

// TestR39_P1_02_CreateProposal_RejectsUnsetChainIDOrNonce verifies the
// bug-class guards: a proposal missing ChainID or Nonce (i.e. a caller that
// tries to bypass the invariant by leaving them zero) is rejected. Without
// this gate, an attacker could ship a proposal that
// VerifyProposalHash cannot recompute (no nonce), letting the legacy trust
// path slip through.
func TestR39_P1_02_CreateProposal_RejectsUnsetChainIDOrNonce(t *testing.T) {
	store := NewMultisigStateStore()
	wallet := r39P102Wallet(t, store)
	to := types.Address{0x0F}
	walletConfig := store.GetWallet(wallet)

	// Missing ChainID.
	pNoChain := makeCanonicalProposal(t, 1668, wallet, to, big.NewInt(100), nil, 0x0102030405, 9_999)
	pNoChain.ChainID = 0
	if err := store.CreateProposal(pNoChain, walletConfig); err == nil {
		t.Fatal("CreateProposal MUST reject proposal with ChainID == 0 (R39-P1-02 invariant)")
	}

	// Missing Nonce.
	pNoNonce := makeCanonicalProposal(t, 1668, wallet, to, big.NewInt(100), nil, 0x0102030405, 9_999)
	pNoNonce.Nonce = 0
	if err := store.CreateProposal(pNoNonce, walletConfig); err == nil {
		t.Fatal("CreateProposal MUST reject proposal with Nonce == 0 (R39-P1-02 invariant)")
	}
}

// TestR39_P1_02_VerifyProposalHash_FallbackToWalletAddr verifies the V1
// compat path: a Proposal constructed WITHOUT HashWalletAddr (zero) falls
// back to using WalletAddr as the hash-input wallet, so legacy V1 callers
// that only set WalletAddr still produce a proposal that verifies under the
// invariant.
func TestR39_P1_02_VerifyProposalHash_FallbackToWalletAddr(t *testing.T) {
	wallet := types.Address{0x0A, 0x0B, 0x0C}
	to := types.Address{0x0F}
	const chainID = uint64(1668)
	const nonce = uint64(0x0102030405)
	const expiresAt = uint64(9_999)
	value := big.NewInt(100)

	// Canonical hash over `wallet`.
	h, err := types.ComputeMultisigV2ProposalHash(chainID, wallet, to, value, nil, nonce, expiresAt)
	if err != nil {
		t.Fatalf("ComputeMultisigV2ProposalHash: %v", err)
	}

	// Proposal sets ONLY WalletAddr; HashWalletAddr is left zero. The
	// invariant must recompute using WalletAddr and verify OK.
	p := &Proposal{
		Hash:       h,
		WalletAddr: wallet,
		To:         to,
		Value:      value,
		ChainID:    chainID,
		Nonce:      nonce,
		ExpiresAt:  int64(expiresAt),
	}
	ok, err := VerifyProposalHash(p)
	if err != nil {
		t.Fatalf("VerifyProposalHash returned err: %v", err)
	}
	if !ok {
		t.Fatal("VerifyProposalHash MUST accept a V1-compat proposal (WalletAddr used as hash wallet, no HashWalletAddr set)")
	}
}

// TestR39_P1_02_VerifyProposalHash_HashWalletAddr_DistinctFromWalletAddr
// verifies the V2 path: when HashWalletAddr is set to a value DIFFERENT
// from WalletAddr (the V2-derived wallet vs the V1 caller cache key), the
// invariant recomputes with HashWalletAddr and rejects a proposal whose
// Hash was computed from WalletAddr instead. This is the actual production
// V2 layout and pins it against accidental regression to "use WalletAddr
// for the hash".
func TestR39_P1_02_VerifyProposalHash_HashWalletAddr_DistinctFromWalletAddr(t *testing.T) {
	callerCacheKey := types.Address{0x11} // WalletAddr (V1 cache key, V1 caller EOA)
	v2Wallet := types.Address{0x22}       // HashWalletAddr (V2-derived)
	to := types.Address{0x0F}
	const chainID = uint64(1668)
	const nonce = uint64(0x55AA55AA)
	const expiresAt = uint64(123_456)
	value := big.NewInt(7)

	// Canonical hash over the V2 wallet (correct V2 layout).
	hV2, err := types.ComputeMultisigV2ProposalHash(chainID, v2Wallet, to, value, nil, nonce, expiresAt)
	if err != nil {
		t.Fatalf("ComputeMultisigV2ProposalHash: %v", err)
	}
	// Hash computed (incorrectly) over the V1 cache key.
	hWrong, err := types.ComputeMultisigV2ProposalHash(chainID, callerCacheKey, to, value, nil, nonce, expiresAt)
	if err != nil {
		t.Fatalf("ComputeMultisigV2ProposalHash (wrong): %v", err)
	}

	// V2-correct proposal: invariant uses HashWalletAddr → verifies OK.
	pV2 := &Proposal{
		Hash:           hV2,
		WalletAddr:     callerCacheKey,
		HashWalletAddr: v2Wallet,
		To:             to,
		Value:          value,
		ChainID:        chainID,
		Nonce:          nonce,
		ExpiresAt:      int64(expiresAt),
	}
	if ok, err := VerifyProposalHash(pV2); err != nil || !ok {
		t.Fatalf("VerifyProposalHash MUST accept V2 proposal (HashWalletAddr=v2, hash=v2): err=%v ok=%v", err, ok)
	}

	// Mismatched V2 proposal: Hash computed over V1 cache key but
	// HashWalletAddr set to v2Wallet → invariant recomputes with v2Wallet
	// and compares to a v1-based hash → MUST fail.
	pMismatched := &Proposal{
		Hash:           hWrong,
		WalletAddr:     callerCacheKey,
		HashWalletAddr: v2Wallet,
		To:             to,
		Value:          value,
		ChainID:        chainID,
		Nonce:          nonce,
		ExpiresAt:      int64(expiresAt),
	}
	if ok, err := VerifyProposalHash(pMismatched); err == nil && ok {
		t.Fatal("VerifyProposalHash MUST reject a proposal whose Hash was computed over WalletAddr but whose HashWalletAddr points elsewhere (V2 mismatch)")
	}
}
